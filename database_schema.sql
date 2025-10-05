-- Extensions 
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- for gen_random_uuid() & digest()
CREATE EXTENSION IF NOT EXISTS citext;    -- case-insensitive text

-- Namespace / search_path 
CREATE SCHEMA IF NOT EXISTS open_share AUTHORIZATION CURRENT_USER;
SET search_path = open_share, public;

-- ENUMS & helper types
-- Protocol version can be a simple textual field; example enum for device status.
CREATE TYPE device_status AS ENUM ('active','revoked','suspended','pending');

-- ACCOUNTS 
-- Uses citext for email uniqueness (case-insensitive).
CREATE TABLE open_share.accounts (
  id                 uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  email              citext      NOT NULL UNIQUE,
  email_verified     boolean     NOT NULL DEFAULT false,
  display_name       text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  disabled           boolean     NOT NULL DEFAULT false,
  metadata           jsonb       DEFAULT '{}'::jsonb,
  -- application-specific fields
  last_signin_at     timestamptz,
  constraints        text
);

COMMENT ON TABLE open_share.accounts IS 'Accounts / users. Email stored case-insensitively using citext.';
CREATE INDEX ON open_share.accounts (created_at);
CREATE INDEX ON open_share.accounts ((lower(email)));  -- expression index for safe lookups

-- Trigger to keep updated_at current on update
CREATE FUNCTION open_share.update_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_accounts_updated_at
BEFORE UPDATE ON open_share.accounts
FOR EACH ROW EXECUTE FUNCTION open_share.update_updated_at();

-- DEVICES & CERTIFICATES 
-- Devices are primary identities; device_uid can be protocol-facing string (retain original IDs).
CREATE TABLE open_share.devices (
  id               uuid          NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(), -- internal PK
  device_uid       text          NOT NULL UNIQUE, -- protocol device_id (stable string)
  account_id       uuid          NOT NULL REFERENCES open_share.accounts(id) ON DELETE CASCADE,
  status           device_status NOT NULL DEFAULT 'pending',
  pubkey_ed25519   bytea         NOT NULL, -- raw pubkey bytes (32 bytes for Ed25519)
  pubkey_b64       text, -- optional cache of base64url for convenience
  cert_blob        jsonb, -- signed certificate JSON as returned to device (canonical form)
  cert_sig         bytea, -- server signature bytes as binary
  cert_issued_at   timestamptz,
  cert_expires_at  timestamptz,
  last_seen        timestamptz,
  created_at       timestamptz    NOT NULL DEFAULT now(),
  updated_at       timestamptz    NOT NULL DEFAULT now(),
  metadata         jsonb DEFAULT '{}'::jsonb
);

COMMENT ON TABLE open_share.devices IS 'Devices registered by accounts. Stores device pubkey, cert blob and metadata.';
CREATE INDEX ON open_share.devices (account_id);
CREATE INDEX ON open_share.devices (status);
CREATE INDEX ON open_share.devices (last_seen);
-- Index to speed up pubkey lookups: index on digest(pubkey, 'sha256')
CREATE INDEX idx_devices_pubkey_digest ON open_share.devices ((digest(pubkey_ed25519, 'sha256')));

-- update timestamp trigger
CREATE TRIGGER trg_devices_updated_at
BEFORE UPDATE ON open_share.devices
FOR EACH ROW EXECUTE FUNCTION open_share.update_updated_at();

-- CERTIFICATE HISTORY (AUDITABLE)
-- Keep a history of issued certificates; useful for rotation and auditing.
CREATE TABLE open_share.device_certs (
  id               uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        uuid        NOT NULL REFERENCES open_share.devices(id) ON DELETE CASCADE,
  cert_blob        jsonb       NOT NULL,
  cert_sig         bytea       NOT NULL,
  issued_at        timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  issuer_id        text, -- server instance id
  revoked_at       timestamptz,
  revoked_reason   text
);

CREATE INDEX ON open_share.device_certs (device_id);
CREATE INDEX ON open_share.device_certs (issued_at);
CREATE INDEX ON open_share.device_certs (expires_at);

-- CRL (Certificate Revocation List) 
-- We Keep CRL as an authoritative signed blob plus separate entries for quick joins.
CREATE TABLE open_share.crls (
  id            bigserial    NOT NULL PRIMARY KEY,
  version       integer      NOT NULL UNIQUE, -- monotonic
  issuer_id     text         NOT NULL,
  issued_at     timestamptz  NOT NULL DEFAULT now(),
  crl_blob      jsonb        NOT NULL, -- canonicalized json list & metadata
  sig           bytea        NOT NULL,
  notes         text
);

COMMENT ON TABLE open_share.crls IS 'Authority-signed CRL blobs. Devices should fetch latest version.';

-- Entries for quick membership testing (denormalized for joins)
CREATE TABLE open_share.crl_entries (
  crl_id        bigint       NOT NULL REFERENCES open_share.crls(id) ON DELETE CASCADE,
  revoked_device_id uuid     NOT NULL REFERENCES open_share.devices(id) ON DELETE CASCADE,
  revoked_at    timestamptz,
  reason        text,
  PRIMARY KEY (crl_id, revoked_device_id)
);

CREATE INDEX ON open_share.crl_entries (revoked_device_id);

-- Convenience materialized view / pointer for current CRL (small helper)
CREATE TABLE open_share.current_crl (
  id          integer PRIMARY KEY CHECK (id = 1),
  crl_id      bigint REFERENCES open_share.crls(id),
  updated_at  timestamptz DEFAULT now()
);
-- Seed with null pointer
INSERT INTO open_share.current_crl (id, crl_id) VALUES (1, NULL)
ON CONFLICT DO NOTHING;

-- PAIRING TOKENS (OFFLINE QR/TOKEN)
CREATE TABLE open_share.pairing_tokens (
  token            text        NOT NULL PRIMARY KEY, -- opaque short token (could be base64/JWS)
  issued_by_device uuid        REFERENCES open_share.devices(id) ON DELETE SET NULL,
  new_pubkey       bytea, -- optional: pre-provisioned pubkey
  issued_at        timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  used             boolean     NOT NULL DEFAULT false,
  used_at          timestamptz,
  metadata         jsonb DEFAULT '{}'::jsonb
);

CREATE INDEX ON open_share.pairing_tokens (issued_by_device);
CREATE INDEX ON open_share.pairing_tokens (expires_at);
-- Partial index for active tokens
CREATE INDEX idx_active_pairing_tokens ON open_share.pairing_tokens (token) WHERE (used = false AND expires_at > now());

-- MANIFESTS & FILE METADATA 
CREATE TABLE open_share.file_manifests (
  manifest_id      uuid         NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest_hash    text         UNIQUE, -- optional: canonical manifest hash (sha256 hex)
  sender_device_id uuid         NOT NULL REFERENCES open_share.devices(id) ON DELETE CASCADE,
  account_id       uuid         NOT NULL REFERENCES open_share.accounts(id) ON DELETE CASCADE,
  filename         text         NOT NULL,
  size             bigint       NOT NULL CHECK (size >= 0),
  chunk_count      integer      NOT NULL DEFAULT 0,
  chunk_size       integer,
  dedup            boolean      NOT NULL DEFAULT true,
  content_type     text,
  manifest_blob    jsonb        NOT NULL, -- full manifest JSON (signed)
  sender_sig       bytea,
  created_at       timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX ON open_share.file_manifests (sender_device_id);
CREATE INDEX ON open_share.file_manifests (account_id);
CREATE INDEX ON open_share.file_manifests (created_at);
-- Index on manifest_hash for quick lookup
CREATE INDEX ON open_share.file_manifests (manifest_hash);

-- CHUNKS (DEDUPED STORE) 
-- chunk_id is canonical SHA-256 string (hex or base64prefixed). Serve chunks by id.
CREATE TABLE open_share.chunks (
  chunk_id        text        NOT NULL PRIMARY KEY, -- e.g. sha256:<hex> or base64url
  size            integer     NOT NULL CHECK (size >= 0),
  storage_url     text,       -- preferred: object storage URL (S3, signed URL), or local path
  storage_backend text,       -- e.g. 's3','local'
  refcount        integer     NOT NULL DEFAULT 0, -- number of manifests referencing it
  created_at      timestamptz NOT NULL DEFAULT now(),
  metadata        jsonb       DEFAULT '{}'::jsonb
);

-- if we expect billions of chunks, we should partition by date or hash prefix.
CREATE INDEX ON open_share.chunks (size);
CREATE INDEX ON open_share.chunks ((left(chunk_id, 8))); -- prefix index for shard lookups

-- MANIFEST -> CHUNK MAPPING (ordered)
CREATE TABLE open_share.manifest_chunks (
  manifest_id    uuid      NOT NULL REFERENCES open_share.file_manifests(manifest_id) ON DELETE CASCADE,
  sequence       integer   NOT NULL, -- order within file (0-based)
  chunk_id       text      NOT NULL REFERENCES open_share.chunks(chunk_id) ON DELETE RESTRICT,
  PRIMARY KEY (manifest_id, sequence)
);

CREATE INDEX ON open_share.manifest_chunks (chunk_id);

-- DELIVERY / TRANSFER SESSIONS 
CREATE TABLE open_share.transfer_sessions (
  id              uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest_id     uuid        REFERENCES open_share.file_manifests(manifest_id) ON DELETE SET NULL,
  sender_device_id uuid       REFERENCES open_share.devices(id) ON DELETE SET NULL,
  receiver_device_id uuid     REFERENCES open_share.devices(id) ON DELETE SET NULL,
  session_key_info jsonb, -- derived session metadata (non-secret), e.g. kdf params
  transport       text,    -- 'quic','tcp','tls'
  state           text,    -- 'initiated','in_progress','completed','aborted'
  started_at      timestamptz DEFAULT now(),
  ended_at        timestamptz
);

CREATE INDEX ON open_share.transfer_sessions (sender_device_id);
CREATE INDEX ON open_share.transfer_sessions (receiver_device_id);
CREATE INDEX ON open_share.transfer_sessions (state);

-- AUTH SESSIONS & TOKENS 
CREATE TABLE open_share.auth_sessions (
  token           uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id      uuid        REFERENCES open_share.accounts(id) ON DELETE CASCADE,
  device_id       uuid        REFERENCES open_share.devices(id) ON DELETE SET NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  last_used_at    timestamptz,
  metadata        jsonb DEFAULT '{}'::jsonb
);

CREATE INDEX ON open_share.auth_sessions (account_id);
CREATE INDEX ON open_share.auth_sessions (expires_at);

-- AUDIT LOG (append-only) 
CREATE TABLE open_share.audit_log (
  id              bigserial   NOT NULL PRIMARY KEY,
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  actor           text, -- e.g. 'user:acct-xx' or 'system'
  action          text NOT NULL, -- e.g. 'device.register', 'cert.revoke'
  entity_type     text, -- e.g. 'device','cert','crl','manifest'
  entity_id       text,
  payload         jsonb DEFAULT '{}'::jsonb, -- change details
  correlation_id  uuid -- optional correlation id for tracing
);

CREATE INDEX ON open_share.audit_log (occurred_at);
CREATE INDEX ON open_share.audit_log (actor);
CREATE INDEX ON open_share.audit_log (entity_type, entity_id);

-- UTILITY: FUNCTIONS & TRIGGERS 
-- Function to check if a device is revoked by consulting current_crl / crl_entries
CREATE OR REPLACE FUNCTION open_share.is_device_revoked(did uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM open_share.current_crl cc
    JOIN open_share.crl_entries ce ON ce.crl_id = cc.crl_id
    WHERE cc.crl_id IS NOT NULL AND ce.revoked_device_id = did
  );
$$;

-- Function to increment/decrement chunk refcount atomically (used by app logic)
CREATE OR REPLACE FUNCTION open_share.increment_chunk_refcount(cid text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  UPDATE open_share.chunks SET refcount = refcount + 1 WHERE chunk_id = cid;
END;
$$;

CREATE OR REPLACE FUNCTION open_share.decrement_chunk_refcount(cid text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  UPDATE open_share.chunks SET refcount = GREATEST(refcount - 1, 0) WHERE chunk_id = cid;
END;
$$;

-- MAINTENANCE & PERFORMANCE NOTES 
-- * Use connection pooling (PgBouncer) in transaction-pool mode.
-- * Consider partitioning "chunks" and "audit_log" if massive: e.g. PARTITION BY RANGE (created_at).
-- * Keep metadata JSONB GIN-indexed for queries that filter on metadata:
CREATE INDEX IF NOT EXISTS idx_devices_metadata_gin ON open_share.devices USING gin (metadata jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_manifests_metadata_gin ON open_share.file_manifests USING gin (manifest_blob);

-- EXAMPLE: materialized view for active devices per account 
CREATE MATERIALIZED VIEW IF NOT EXISTS open_share.active_devices_by_account AS
SELECT a.id as account_id, count(d.*) as active_device_count
FROM open_share.accounts a
LEFT JOIN open_share.devices d ON d.account_id = a.id AND d.status = 'active'
GROUP BY a.id;

COMMENT ON SCHEMA open_share IS 'Open Share protocol schema for registration server, CRL, manifests, chunks and pairing tokens.';
