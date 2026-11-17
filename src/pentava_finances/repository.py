"""Encrypted transaction persistence for Google identities (SQLite on persistent volume)."""
import sqlite3
import time
import uuid
from .identity import User, database


class RecordRequestError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code


class RecordUnavailableError(Exception):
    pass


async def list_transaction_records(user, page, per_page):
    try:
        with database() as db:
            total = db.execute('SELECT COUNT(*) FROM records WHERE owner=?', (user.id,)).fetchone()[0]
            rows = db.execute('SELECT * FROM records WHERE owner=? ORDER BY created DESC,id DESC LIMIT ? OFFSET ?', (user.id, per_page, (page-1)*per_page)).fetchall()
        return {'page':page,'perPage':per_page,'totalItems':total,'totalPages':(total+per_page-1)//per_page,'items':[dict(row) for row in rows]}
    except sqlite3.Error as error:
        raise RecordUnavailableError('Transaction storage is unavailable.') from error


async def get_transaction_record(user, record_id):
    try:
        with database() as db:
            row = db.execute('SELECT * FROM records WHERE id=? AND owner=?', (record_id,user.id)).fetchone()
        if row is None:
            raise RecordRequestError(404)
        return dict(row)
    except sqlite3.Error as error:
        raise RecordUnavailableError('Transaction storage is unavailable.') from error


async def create_transaction_record(user, encrypted_payload, client_event_id=None):
    try:
        record_id = 'rec_' + uuid.uuid4().hex
        with database() as db:
            db.execute('INSERT OR IGNORE INTO records VALUES(?,?,?,?,?)', (record_id, user.id, encrypted_payload, client_event_id, time.time()))
            if client_event_id:
                row = db.execute('SELECT * FROM records WHERE owner=? AND event_id=?', (user.id,client_event_id)).fetchone()
            else:
                row = db.execute('SELECT * FROM records WHERE id=? AND owner=?', (record_id,user.id)).fetchone()
        return dict(row)
    except sqlite3.Error as error:
        raise RecordUnavailableError('Transaction storage is unavailable.') from error


async def update_transaction_record(user, record_id, encrypted_payload):
    await get_transaction_record(user,record_id)
    try:
        with database() as db:
            db.execute('UPDATE records SET encrypted_payload=? WHERE id=? AND owner=?', (encrypted_payload,record_id,user.id))
        return await get_transaction_record(user,record_id)
    except sqlite3.Error as error:
        raise RecordUnavailableError('Transaction storage is unavailable.') from error


async def delete_transaction_record(user, record_id):
    await get_transaction_record(user,record_id)
    try:
        with database() as db:
            db.execute('DELETE FROM records WHERE id=? AND owner=?', (record_id,user.id))
    except sqlite3.Error as error:
        raise RecordUnavailableError('Transaction storage is unavailable.') from error
