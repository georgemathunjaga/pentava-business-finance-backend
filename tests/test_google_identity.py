import hashlib
import time
import pytest
from fastapi.testclient import TestClient
from pentava_finances.main import app
from pentava_finances import identity
from pentava_finances.identity import database, User
from pentava_finances.repository import create_transaction_record, get_transaction_record, RecordRequestError

ORIGIN={'Origin':'http://testserver'}

@pytest.fixture
def setup(monkeypatch,tmp_path):
    monkeypatch.setenv('DATA_DIRECTORY',str(tmp_path))
    monkeypatch.setenv('GOOGLE_CLIENT_ID','fixture.apps.googleusercontent.com')
    monkeypatch.setenv('SESSION_COOKIE_SECURE','false')
    claims={'sub':'google-subject-one','email':'owner@example.test','name':'Test Owner','email_verified':True,'iss':'https://accounts.google.com','nonce':''}
    def verify(credential,transport,audience):
        assert audience=='fixture.apps.googleusercontent.com'
        if credential=='invalid':raise ValueError('invalid credential')
        return dict(claims)
    monkeypatch.setattr(identity.id_token,'verify_oauth2_token',verify)
    return TestClient(app),claims

def login(client,claims):
    challenge=client.post('/auth/google/challenge',headers=ORIGIN)
    assert challenge.status_code==200
    claims['nonce']=challenge.json()['nonce']
    return client.post('/auth/google/session',json={'credential':'synthetic-id-token'},headers=ORIGIN)

def test_google_cookie_session_and_logout(setup):
    client,claims=setup
    response=login(client,claims)
    assert response.status_code==200
    assert response.json()['user']['email']=='owner@example.test'
    assert 'token' not in response.json()
    assert 'HttpOnly' in response.headers['set-cookie']
    assert client.get('/auth/me').status_code==200
    assert client.post('/auth/logout',headers=ORIGIN).status_code==403
    csrf=response.json()['csrf_token']
    assert client.post('/auth/logout',headers={**ORIGIN,'X-Pentava-CSRF':csrf}).status_code==204
    assert client.get('/auth/me').status_code==401

def test_requires_fresh_challenge(setup):
    client,claims=setup
    assert client.post('/auth/google/session',json={'credential':'synthetic'},headers=ORIGIN).status_code==401
    response=login(client,claims)
    assert response.status_code==200
    assert client.post('/auth/google/session',json={'credential':'synthetic'},headers=ORIGIN).status_code==401

def test_rejects_nonce_mismatch_and_unverified_email(setup):
    client,claims=setup
    client.post('/auth/google/challenge',headers=ORIGIN)
    assert client.post('/auth/google/session',json={'credential':'synthetic'},headers=ORIGIN).status_code==401
    claims['email_verified']=False
    assert login(client,claims).status_code==401

def test_rejects_untrusted_origin_and_invalid_google_credential(setup):
    client,claims=setup
    assert client.post('/auth/google/challenge',headers={'Origin':'https://untrusted.example'}).status_code==403
    challenge=client.post('/auth/google/challenge',headers=ORIGIN)
    claims['nonce']=challenge.json()['nonce']
    assert client.post('/auth/google/session',json={'credential':'invalid'},headers=ORIGIN).status_code==401

def test_session_revoked_or_expired_is_not_authenticated(setup):
    client,claims=setup
    login(client,claims)
    with database() as db:db.execute('UPDATE sessions SET expires=?',(time.time()-1,))
    assert client.get('/auth/me').status_code==401

def test_business_cookie_auth_csrf_and_google_owner_isolation(setup):
    client,claims=setup
    first=login(client,claims).json()
    assert client.post('/businesses',json={'name':'Test'},headers=ORIGIN).status_code==403
    response=client.post('/businesses',json={'name':'Test','owner_name':'Owner','phone':'+254712345678'},headers={**ORIGIN,'X-Pentava-CSRF':first['csrf_token']})
    assert response.status_code==201
    assert response.json()['phone']=='+254712345678'
    biz=response.json()
    assert biz['owner_id']==first['user']['id']
    pair=client.post('/moneychat/pairing-sessions',json={'business_id':biz['id']},headers={**ORIGIN,'X-Pentava-CSRF':first['csrf_token']})
    assert pair.status_code==201
    assert pair.json()['qr_payload'].startswith('moneychat://connect')
    assert client.get('/moneychat/pairing-sessions/'+pair.json()['id']).status_code==200
    claims['sub']='google-subject-two'
    other=TestClient(app)
    assert login(other,claims).status_code==200
    assert other.get('/businesses/'+biz['id']).status_code==404
    assert client.get('/auth/me').json()['businesses'][0]['id']==biz['id']

def test_google_subject_not_email_is_the_identity(setup):
    client,claims=setup
    first=login(client,claims).json()['user']['id']
    claims['email']='renamed@example.test'
    assert login(client,claims).json()['user']['id']==first
    claims['sub']='another-subject'
    assert login(client,claims).json()['user']['id']!=first

def test_sqlite_repository_owner_isolation_and_idempotency(setup):
    import asyncio
    user=User('google_owner')
    record=asyncio.run(create_transaction_record(user,'opaque-ciphertext','event-one'))
    duplicate=asyncio.run(create_transaction_record(user,'opaque-ciphertext','event-one'))
    assert record['id']==duplicate['id']
    with pytest.raises(RecordRequestError):asyncio.run(get_transaction_record(User('other_owner'),record['id']))
    with database() as db:
        assert db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==1
        assert db.execute('SELECT encrypted_payload FROM records').fetchone()[0]=='opaque-ciphertext'

# Additional endpoint checks use an ephemeral RSA key pair and isolated temporary data.
def test_google_session_can_store_encrypted_records_without_pocketbase(setup,monkeypatch,tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    client,claims=setup
    keys=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private=tmp_path/'private.pem';public=tmp_path/'public.pem'
    private.write_bytes(keys.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    public.write_bytes(keys.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv('ENCRYPTION_PRIVATE_KEY_PATH',str(private));monkeypatch.setenv('ENCRYPTION_PUBLIC_KEY_PATH',str(public))
    session=login(client,claims).json()
    headers={**ORIGIN,'X-Pentava-CSRF':session['csrf_token']}
    response=client.post('/transactions',json={'payload':{'reference':'PRIVATE-TEST-001','amount_minor':250000}},headers=headers)
    assert response.status_code==201
    record=response.json()
    assert client.get('/transactions/'+record['id']).json()['payload']['reference']=='PRIVATE-TEST-001'
    with database() as db:
        encrypted=db.execute('SELECT encrypted_payload FROM records WHERE id=?',(record['id'],)).fetchone()[0]
        assert 'PRIVATE-TEST-001' not in encrypted
    claims['sub']='another-owner'
    other=TestClient(app);login(other,claims)
    assert other.get('/transactions/'+record['id']).status_code==404
