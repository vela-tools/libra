-- Principals, their API keys, and the lease that keeps one proxy instance on this store.
--
-- Every table is STRICT, so a value of the wrong type is refused rather than coerced. Timestamps
-- are Unix seconds. Ids and verifiers are raw bytes, with their lengths checked here as well as by
-- the types that write them.

CREATE TABLE principals (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE principal_groups (
    principal BLOB NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    PRIMARY KEY (principal, name)
) STRICT;

CREATE TABLE principal_roles (
    principal BLOB NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    PRIMARY KEY (principal, name)
) STRICT;

CREATE TABLE api_keys (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    principal BLOB NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    verifier BLOB NOT NULL CHECK (length(verifier) = 32),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

CREATE INDEX api_keys_by_principal ON api_keys (principal);

CREATE TABLE instance_lease (
    slot INTEGER PRIMARY KEY NOT NULL CHECK (slot = 1),
    holder BLOB NOT NULL CHECK (length(holder) = 16),
    started_at INTEGER NOT NULL,
    renewed_at INTEGER NOT NULL
) STRICT;
