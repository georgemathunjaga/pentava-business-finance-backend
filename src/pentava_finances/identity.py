"""Google identity + revocable, HttpOnly browser sessions. No PocketBase auth."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(tags=['Identity'])
SESSION_COOKIE = 'pentava_session'
CHALLENGE_COOKIE = 'pentava_google_challenge'
SESSION_TTL = 7 * 24 * 3600


@contextmanager
def database():
    root = Path(os.getenv('DATA_DIRECTORY', str(Path(__file__).resolve().parents[2] / 'data')))
    root.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(root / 'identity.sqlite3', timeout=20)
    db.row_factory = sqlite3.Row
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,google_sub TEXT UNIQUE NOT NULL,email TEXT NOT NULL,name TEXT NOT NULL,picture TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(digest TEXT PRIMARY KEY,user_id TEXT NOT NULL,csrf TEXT NOT NULL,expires REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS challenges(digest TEXT PRIMARY KEY,nonce TEXT NOT NULL,expires REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,owner TEXT NOT NULL,encrypted_payload TEXT NOT NULL,event_id TEXT,created REAL NOT NULL,UNIQUE(owner,event_id));
    ''')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def allowed_origin(request):
    origins = {item.strip().rstrip('/') for item in os.getenv('FRONTEND_ORIGINS', 'http://localhost:15684,http://127.0.0.1:15684').split(',') if item.strip()}
    origins.add(str(request.base_url).rstrip('/'))
    origin = request.headers.get('origin', '').rstrip('/')
    if not origin or origin not in origins:
        raise HTTPException(403, 'This browser origin is not allowed.')


def set_cookie(response, name, value, request, max_age):
    secure = os.getenv('SESSION_COOKIE_SECURE', 'false' if request.url.hostname in ('localhost', '127.0.0.1', 'testserver') else 'true').lower() == 'true'
    same_site = os.getenv('SESSION_COOKIE_SAMESITE', 'lax')
    response.set_cookie(name, value, httponly=True, secure=secure, samesite=same_site, max_age=max_age, path='/')


@dataclass
class User:
    id: str
    email: str = ''
    name: str = ''
    picture: str = ''
    token: str = ''
    csrf: str = ''
    device_id: str | None = None
    business_id: str | None = None


def user_dict(user):
    return {'id': user.id, 'email': user.email, 'name': user.name, 'picture': user.picture}


def issue_session(user_id, response, request):
    token, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
    with database() as db:
        db.execute('DELETE FROM sessions WHERE expires < ?', (time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)', (digest(token), user_id, csrf, time.time() + SESSION_TTL))
    set_cookie(response, SESSION_COOKIE, token, request, SESSION_TTL)
    return csrf


async def require_user(request: Request) -> User:
    token = request.cookies.get(SESSION_COOKIE, '')
    if token:
        with database() as db:
            row = db.execute('SELECT u.*,s.csrf,s.expires FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.digest=?', (digest(token),)).fetchone()
        if row is None or row['expires'] <= time.time():
            raise HTTPException(401, 'Your session has expired. Sign in with Google again.')
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            allowed_origin(request)
            if not hmac.compare_digest(request.headers.get('x-pentava-csrf', ''), row['csrf']):
                raise HTTPException(403, 'Session verification failed. Reload and try again.')
        return User(id=row['id'], email=row['email'], name=row['name'], picture=row['picture'], csrf=row['csrf'])
    # A phone uses its own scoped device token, never a browser session token.
    bearer = request.headers.get('authorization', '')
    if bearer.startswith('Bearer '):
        import jwt
        from .device_tokens import verify_device_token
        from .storage import get_device
        try:
            claims = verify_device_token(bearer[7:], 'access')
        except jwt.InvalidTokenError as error:
            raise HTTPException(401, 'Device token is invalid or expired.') from error
        device = get_device(claims.get('device_id'))
        if not device or device.get('status') == 'revoked' or device.get('user_id') != claims.get('user_id') or device.get('business_id') != claims.get('business_id'):
            raise HTTPException(401, 'Device connection is no longer valid.')
        allowed = request.method == 'POST' and request.url.path == '/transactions/from-client' or request.method == 'PUT' and request.url.path.startswith('/transactions/') and request.url.path.endswith('/from-client')
        if not allowed:
            raise HTTPException(403, 'This device credential does not permit this action.')
        return User(id=claims['user_id'], device_id=device['id'], business_id=device['business_id'])
    raise HTTPException(401, 'Sign in with Google to continue.')


@router.get('/auth/config')
def auth_config():
    return {'provider': 'google', 'client_id': os.getenv('GOOGLE_CLIENT_ID', ''), 'configured': bool(os.getenv('GOOGLE_CLIENT_ID'))}


@router.post('/auth/google/challenge')
def google_challenge(request: Request, response: Response):
    allowed_origin(request)
    token, nonce = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
    previous = request.cookies.get(CHALLENGE_COOKIE)
    with database() as db:
        db.execute('DELETE FROM challenges WHERE expires < ?', (time.time(),))
        if previous:
            db.execute('DELETE FROM challenges WHERE digest=?', (digest(previous),))
        db.execute('INSERT INTO challenges VALUES(?,?,?)', (digest(token), nonce, time.time()+300))
    set_cookie(response, CHALLENGE_COOKIE, token, request, 300)
    return {'nonce': nonce, 'expires_in': 300}


class GoogleCredential(BaseModel):
    model_config = ConfigDict(extra='forbid')
    credential: str = Field(min_length=1, max_length=12000)


@router.post('/auth/google/session')
def google_session(body: GoogleCredential, request: Request, response: Response):
    allowed_origin(request)
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    if not client_id:
        raise HTTPException(503, 'Google sign-in is not configured.')
    token = request.cookies.get(CHALLENGE_COOKIE, '')
    with database() as db:
        challenge = db.execute('DELETE FROM challenges WHERE digest=? RETURNING nonce,expires', (digest(token),)).fetchone()
    response.delete_cookie(CHALLENGE_COOKIE, path='/')
    if challenge is None or challenge['expires'] <= time.time():
        raise HTTPException(401, 'The sign-in request expired. Please try again.')
    try:
        claims = id_token.verify_oauth2_token(body.credential, GoogleRequest(), client_id)
    except (ValueError, TypeError) as error:
        raise HTTPException(401, 'Google could not verify this sign-in.') from error
    except Exception as error:
        raise HTTPException(503, 'Google verification is temporarily unavailable.') from error
    if claims.get('iss') not in ('accounts.google.com', 'https://accounts.google.com') or claims.get('email_verified') is not True or not claims.get('sub') or not hmac.compare_digest(str(claims.get('nonce','')), challenge['nonce']):
        raise HTTPException(401, 'Google identity verification failed.')
    # Stable Google subject is the identity, not an editable email or display name.
    user_id = 'google_' + hashlib.sha256(claims['sub'].encode()).hexdigest()[:40]
    user = User(user_id, claims.get('email',''), claims.get('name',''), claims.get('picture',''))
    with database() as db:
        db.execute('INSERT INTO users VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,name=excluded.name,picture=excluded.picture', (user.id, claims['sub'], user.email, user.name, user.picture))
    old = request.cookies.get(SESSION_COOKIE)
    if old:
        with database() as db:
            db.execute('DELETE FROM sessions WHERE digest=?', (digest(old),))
    csrf = issue_session(user.id, response, request)
    from .storage import list_user_businesses
    return {'user': user_dict(user), 'businesses': list_user_businesses(user.id), 'csrf_token': csrf}


@router.get('/auth/me')
async def me(request: Request):
    user = await require_user(request)
    from .storage import list_user_businesses
    return {'user': user_dict(user), 'businesses': list_user_businesses(user.id), 'csrf_token': user.csrf}


@router.post('/auth/logout', status_code=204)
async def logout(request: Request, response: Response):
    await require_user(request)
    with database() as db:
        db.execute('DELETE FROM sessions WHERE digest=?', (digest(request.cookies.get(SESSION_COOKIE,'')),))
    response.delete_cookie(SESSION_COOKIE, path='/')
