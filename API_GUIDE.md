# Pentava Business Finances — API Guide

Base URL: `http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs`

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Crypto API](#2-crypto-api)
3. [Transactions API](#3-transactions-api)
4. [Google OAuth](#4-google-oauth)
5. [Google Sheets](#5-google-sheets)
6. [Mobile App Integration](#6-mobile-app-integration)
7. [Error Reference](#7-error-reference)
8. [Environment Variables](#8-environment-variables)

---

## 1. Authentication

Most endpoints require a **PocketBase bearer token** obtained by signing in through your PocketBase instance (`http://localhost:8090` by default).

**Get a token from PocketBase:**
```http
POST http://localhost:8090/api/collections/users/auth-with-password
Content-Type: application/json

{
  "identity": "user@example.com",
  "password": "yourpassword"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "record": { "id": "abc123", ... }
}
```

Pass this token on every protected request:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 2. Crypto API

Encryption scheme: **RSA-3072-OAEP-SHA256** (key wrapping) + **AES-256-GCM** (data encryption).  
The RSA private key never leaves the server. The public key is freely accessible so clients can encrypt locally.

---

### GET /crypto/status

Check that the server's encryption keys are loaded and valid. No auth required.

```http
GET /crypto/status
```

**Response 200:**
```json
{
  "status": "ok",
  "key_id": "local-v1",
  "algorithm": "RSA-OAEP-SHA256 + AES-256-GCM",
  "rsa_key_bits": 3072
}
```

---

### GET /crypto/public-key

Fetch the RSA public key so the mobile app can encrypt data locally. No auth required.  
Cache this key — it only changes if keys are rotated.

```http
GET /crypto/public-key
```

**Response 200:**
```json
{
  "key_id": "local-v1",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkq...\n-----END PUBLIC KEY-----\n"
}
```

> **Mobile apps:** store `key_id` alongside any envelope you produce — the backend uses it to select the correct decryption key.

---

### POST /crypto/encrypt

Encrypt an arbitrary JSON payload server-side. Requires auth.

```http
POST /crypto/encrypt
Authorization: Bearer <token>
Content-Type: application/json

{
  "payload": {
    "amount": 1500.00,
    "currency": "ZAR",
    "description": "Invoice #42"
  }
}
```

**Response 200:**
```json
{
  "envelope": "{\"version\":1,\"key_id\":\"local-v1\",\"nonce\":\"abc...\",\"encrypted_key\":\"xyz...\",\"ciphertext\":\"def...\"}"
}
```

---

### POST /crypto/decrypt

Decrypt an envelope produced by `/crypto/encrypt` or by the mobile app. Requires auth.

```http
POST /crypto/decrypt
Authorization: Bearer <token>
Content-Type: application/json

{
  "envelope": "{\"version\":1,\"key_id\":\"local-v1\",\"nonce\":\"...\",\"encrypted_key\":\"...\",\"ciphertext\":\"...\"}"
}
```

**Response 200:**
```json
{
  "payload": {
    "amount": 1500.00,
    "currency": "ZAR",
    "description": "Invoice #42"
  }
}
```

---

## 3. Transactions API

Transactions are always stored encrypted in PocketBase. The API encrypts/decrypts transparently — responses always return the plaintext `payload`.

All transaction endpoints require a **Bearer token**.

---

### POST /transactions

Create a transaction. The backend encrypts the payload before storing it.

```http
POST /transactions
Authorization: Bearer <token>
Content-Type: application/json

{
  "payload": {
    "amount": 250.00,
    "currency": "ZAR",
    "category": "fuel",
    "note": "Company car"
  }
}
```

**Response 201:**
```json
{
  "id": "rec_abc123",
  "payload": {
    "amount": 250.00,
    "currency": "ZAR",
    "category": "fuel",
    "note": "Company car"
  }
}
```

---

### POST /transactions/from-client

Create a transaction from an envelope **already encrypted on the mobile app**. The backend decrypts only to validate, then stores the envelope as-is. See [Section 6](#6-mobile-app-integration) for how to build the envelope.

```http
POST /transactions/from-client
Authorization: Bearer <token>
Content-Type: application/json

{
  "envelope": "{\"version\":1,\"key_id\":\"local-v1\",\"nonce\":\"...\",\"encrypted_key\":\"...\",\"ciphertext\":\"...\"}"
}
```

**Response 201:**
```json
{
  "id": "rec_abc123",
  "payload": {
    "amount": 250.00,
    "currency": "ZAR",
    "category": "fuel"
  }
}
```

**Error 422** — envelope is malformed or encrypted with the wrong key:
```json
{ "detail": "The envelope could not be decrypted — verify the encryption scheme and key_id." }
```

---

### GET /transactions

List all transactions belonging to the authenticated user, newest first.

```http
GET /transactions?page=1&per_page=30
Authorization: Bearer <token>
```

| Query param | Type | Default | Max |
|---|---|---|---|
| `page` | integer | 1 | — |
| `per_page` | integer | 30 | 100 |

**Response 200:**
```json
{
  "page": 1,
  "per_page": 30,
  "total_items": 2,
  "total_pages": 1,
  "items": [
    { "id": "rec_abc123", "payload": { "amount": 250.00, "currency": "ZAR" } },
    { "id": "rec_def456", "payload": { "amount": 80.00,  "currency": "ZAR" } }
  ]
}
```

---

### GET /transactions/{id}

Fetch a single transaction by ID.

```http
GET /transactions/rec_abc123
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "id": "rec_abc123",
  "payload": {
    "amount": 250.00,
    "currency": "ZAR",
    "category": "fuel"
  }
}
```

---

### PUT /transactions/{id}

Replace a transaction's payload. The backend re-encrypts the new payload.

```http
PUT /transactions/rec_abc123
Authorization: Bearer <token>
Content-Type: application/json

{
  "payload": {
    "amount": 275.00,
    "currency": "ZAR",
    "category": "fuel",
    "note": "Updated amount"
  }
}
```

**Response 200:** same shape as GET.

---

### PUT /transactions/{id}/from-client

Replace a transaction using a pre-encrypted envelope from the mobile app.

```http
PUT /transactions/rec_abc123/from-client
Authorization: Bearer <token>
Content-Type: application/json

{
  "envelope": "{\"version\":1,\"key_id\":\"local-v1\",\"nonce\":\"...\",\"encrypted_key\":\"...\",\"ciphertext\":\"...\"}"
}
```

**Response 200:** same shape as GET.

---

### DELETE /transactions/{id}

Delete a transaction permanently.

```http
DELETE /transactions/rec_abc123
Authorization: Bearer <token>
```

**Response 204** — no body.

---

## 4. Google OAuth

Connects the backend to a Google account so it can read/write Google Sheets.

---

### GET /auth/google

Redirect the browser here to start the Google OAuth flow.

```http
GET /auth/google
```

Redirects to Google's consent screen. After the user approves, Google redirects to `/auth/google/callback`.

---

### GET /auth/google/callback

Handled automatically by the backend — Google redirects here after consent.  
You do not call this directly.

**Response 200 (on success):**
```json
{
  "success": true,
  "message": "Google account connected successfully."
}
```

---

## 5. Google Sheets

Requires the Google account to be connected first (see Section 4).

---

### POST /google/sheets

Create a new Google Spreadsheet pre-formatted with the standard transaction columns. The header row is bold, dark-background, and frozen. All columns are sized to fit their content.

```http
POST /google/sheets
Content-Type: application/json

{
  "title": "Pentava Expenses — Jan 2025",
  "sheet_name": "Transactions"
}
```

| Field | Type | Required | Default |
|---|---|---|---|
| `title` | string | Yes | — |
| `sheet_name` | string | No | `"Transactions"` |

**Response 201:**
```json
{
  "success": true,
  "spreadsheet_id": "1BxiMVs...",
  "url": "https://docs.google.com/spreadsheets/d/1BxiMVs.../edit",
  "title": "Pentava Expenses — Jan 2025",
  "sheet_name": "Transactions",
  "headers": ["Date", "Amount", "Currency", "Type", "Category", "Description", "Reference", "Recorded By"]
}
```

**Pre-filled columns:**

| Column | Purpose |
|---|---|
| Date | Transaction date (YYYY-MM-DD) |
| Amount | Numeric value |
| Currency | ISO code e.g. `KES`, `ZAR` |
| Type | `income` or `expense` |
| Category | e.g. `fuel`, `meals`, `salary` |
| Description | Free-text note |
| Reference | Invoice / receipt number |
| Recorded By | Device or user label |

---

### GET /google/sheets

List all Google Sheets spreadsheets accessible to the connected account.

```http
GET /google/sheets?page_token=<optional>
```

**Response 200:**
```json
{
  "success": true,
  "files": [
    { "id": "1BxiMVs...", "name": "Pentava Expenses 2024" }
  ],
  "nextPageToken": null
}
```

---

### GET /google/sheets/{spreadsheet_id}

Get metadata for a specific spreadsheet.

```http
GET /google/sheets/1BxiMVs...
```

**Response 200:**
```json
{
  "success": true,
  "spreadsheet": {
    "spreadsheetId": "1BxiMVs...",
    "properties": { "title": "Pentava Expenses 2024" },
    "sheets": [ ... ]
  }
}
```

---

### GET /google/sheets/{spreadsheet_id}/values

Read cell values from a sheet range.

```http
GET /google/sheets/1BxiMVs.../values?range=Sheet1!A1:E100
```

| Query param | Default |
|---|---|
| `range` | `Sheet1!A1:Z100` |

**Response 200:**
```json
{
  "success": true,
  "range": "Sheet1!A1:E5",
  "values": [
    ["Date",   "Amount", "Category"],
    ["2024-01-15", "250", "fuel"]
  ]
}
```

---

### POST /google/sheets/{spreadsheet_id}/values

Append a row to a sheet.

```http
POST /google/sheets/1BxiMVs.../values?range=Sheet1!A:E
Content-Type: application/json

{
  "values": ["2024-01-16", 150.00, "meals", "Team lunch"]
}
```

**Response 200:**
```json
{
  "success": true,
  "updated": { ... }
}
```

---

## 6. Mobile App Integration

The recommended flow for a mobile app that handles sensitive financial data:

### Step 1 — Authenticate with PocketBase

```js
const res = await fetch('http://localhost:8090/api/collections/users/auth-with-password', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ identity: email, password }),
});
const { token } = await res.json();
```

### Step 2 — Fetch and cache the public key

```js
const res = await fetch('http://localhost:8000/crypto/public-key');
const { key_id, public_key } = await res.json();
// cache public_key and key_id — only re-fetch if key_id changes
```

### Step 3 — Encrypt on the device

Use the RSA public key with **RSA-OAEP-SHA256** to wrap a fresh **AES-256-GCM** key, then encrypt the payload. Libraries:

| Platform | Library |
|---|---|
| React Native | `react-native-quick-crypto` |
| iOS (Swift) | `Security` framework / `CryptoKit` |
| Android (Kotlin) | `javax.crypto` / `java.security` |

The envelope must be a JSON **string** in this exact shape:

```json
{
  "version": 1,
  "key_id": "local-v1",
  "nonce": "<base64url, 12 bytes>",
  "encrypted_key": "<base64url, RSA-OAEP-SHA256 wrapped AES-256 key>",
  "ciphertext": "<base64url, AES-256-GCM ciphertext + 16-byte auth tag>"
}
```

Associated data bound to the ciphertext (must be identical on both sides):
```
pentava-transactions:v1:local-v1
```

### Step 4 — Push to the backend

```js
const envelope = JSON.stringify({
  version: 1,
  key_id,
  nonce: toBase64Url(nonce),
  encrypted_key: toBase64Url(wrappedKey),
  ciphertext: toBase64Url(ciphertext),
});

const res = await fetch('http://localhost:8000/transactions/from-client', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ envelope }),
});

const { id, payload } = await res.json(); // 201 Created
```

---

## 7. Error Reference

| Status | Meaning |
|---|---|
| `400` | Bad request — malformed input |
| `401` | Missing or invalid bearer token |
| `403` | Token valid but access denied to this resource |
| `404` | Record not found |
| `422` | Envelope could not be decrypted |
| `500` | Stored record is corrupted or unreadable |
| `502` | PocketBase or Google API is unreachable |
| `503` | Encryption keys are missing or misconfigured |

---

## 8. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GOOGLE_CLIENT_ID` | Yes | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | — | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | No | `http://localhost:8000/auth/google/callback` | Must match Google Cloud Console exactly |
| `GOOGLE_TOKEN_DIRECTORY` | No | `tokens/` | Where OAuth tokens are saved |
| `POCKETBASE_URL` | No | `http://127.0.0.1:8090` | PocketBase instance URL |
| `POCKETBASE_USERS_COLLECTION` | No | `users` | PocketBase users collection name |
| `POCKETBASE_TRANSACTIONS_COLLECTION` | No | `transactions` | PocketBase transactions collection name |
| `ENCRYPTION_PUBLIC_KEY_PATH` | No | `keys/public.pem` | Path to RSA public key |
| `ENCRYPTION_PRIVATE_KEY_PATH` | No | `keys/private.pem` | Path to RSA private key |
| `ENCRYPTION_KEY_ID` | No | `local-v1` | Key identifier included in every envelope |

**Generate encryption keys (run once):**
```bash
python -m pentava_finances.generate_keys
```

**Start the server:**
```bash
python run.py
# or
uvicorn pentava_finances.main:app --reload --port 8000
```
