-- Device HMAC keys are stored only as AES-256-GCM ciphertext (see crypto.go).
-- Device WireGuard private keys are never stored.
CREATE TABLE devices (
    id               TEXT PRIMARY KEY,
    ip               TEXT NOT NULL UNIQUE,
    key_id           TEXT NOT NULL DEFAULT '',
    hmac_enc         BLOB NOT NULL,
    prev_key_id      TEXT NOT NULL DEFAULT '',
    prev_hmac_enc    BLOB,
    pending_key_id   TEXT NOT NULL DEFAULT '',
    pending_hmac_enc BLOB,
    wg_pubkey        TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    disabled         INTEGER NOT NULL DEFAULT 0
);

-- Passwords are argon2id hashes; session tokens are stored as SHA-256 only.
CREATE TABLE users (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    pw_hash    TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX sessions_expires ON sessions(expires_at);

CREATE TABLE audit (
    id        INTEGER PRIMARY KEY,
    at        INTEGER NOT NULL,
    user      TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    result    TEXT NOT NULL DEFAULT ''
);
