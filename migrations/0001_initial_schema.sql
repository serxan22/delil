-- DƏLİL schema version 1.
--
-- Hierarchy: tenants -> projects -> audit_streams -> audit_events.
--
-- Integrity does not depend on anything in this file: every event is hashed,
-- linked and signed, and verification recomputes all of it. The constraints
-- and triggers below are defence in depth. They stop application bugs and
-- accidental writes, and give the runtime role no way to rewrite history, but
-- a superuser or the table owner can disable triggers. Verification is what
-- detects that. See docs/security.md.

-- ---------------------------------------------------------------------------
-- Tenancy

CREATE TABLE tenants (
    id         text PRIMARY KEY CHECK (id ~ '^org_[0-9A-Z]{26}$'),
    slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id         text PRIMARY KEY CHECK (id ~ '^prj_[0-9A-Z]{26}$'),
    tenant_id  text NOT NULL REFERENCES tenants (id),
    slug       text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    settings   jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug),
    UNIQUE (tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Dashboard users and sessions

CREATE TABLE users (
    id            text PRIMARY KEY CHECK (id ~ '^usr_[0-9A-Z]{26}$'),
    tenant_id     text NOT NULL REFERENCES tenants (id),
    email         text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320),
    display_name  text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'auditor', 'viewer')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    disabled_at   timestamptz
);
CREATE INDEX users_tenant_idx ON users (tenant_id);

CREATE TABLE sessions (
    id           text PRIMARY KEY CHECK (id ~ '^ses_[0-9A-Z]{26}$'),
    token_hash   bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id    text NOT NULL REFERENCES tenants (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz,
    ip           text,
    user_agent   text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- API keys: only SHA-256(full key) is stored. lookup_id is the public part
-- embedded in the key and is used to find the row.

CREATE TABLE api_keys (
    id           text PRIMARY KEY CHECK (id ~ '^key_[0-9A-Z]{26}$'),
    tenant_id    text NOT NULL,
    project_id   text NOT NULL,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    lookup_id    text NOT NULL UNIQUE CHECK (lookup_id ~ '^[a-z2-7]{16}$'),
    secret_hash  bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    scopes       text[] NOT NULL CHECK (cardinality(scopes) > 0),
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE INDEX api_keys_project_idx ON api_keys (project_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Signing keys. Public keys are kept forever so history stays verifiable.
-- Private material is never stored here in plaintext: either it lives outside
-- the database (file, KMS, HSM) and provider_ref points at it, or it is
-- wrapped with AES-256-GCM under a key derived from the master key.

CREATE TABLE signing_keys (
    id                  text PRIMARY KEY CHECK (id ~ '^ed25519:[0-9a-f]{32}$'),
    tenant_id           text NOT NULL,
    project_id          text NOT NULL,
    algorithm           text NOT NULL CHECK (algorithm = 'Ed25519'),
    public_key          bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    fingerprint         text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    provider            text NOT NULL,
    provider_ref        text,
    wrapped_private_key bytea,
    status              text NOT NULL CHECK (status IN ('active', 'retired', 'revoked')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    activated_at        timestamptz NOT NULL,
    retired_at          timestamptz,
    revoked_at          timestamptz,
    revocation_reason   text,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id),
    CHECK (status <> 'retired' OR retired_at IS NOT NULL),
    CHECK (status <> 'revoked' OR revoked_at IS NOT NULL)
);
CREATE UNIQUE INDEX signing_keys_one_active_per_project ON signing_keys (project_id) WHERE status = 'active';
CREATE INDEX signing_keys_project_idx ON signing_keys (project_id, activated_at);

-- ---------------------------------------------------------------------------
-- Streams and events

CREATE TABLE audit_streams (
    id                       text PRIMARY KEY CHECK (id ~ '^str_[0-9A-Z]{26}$'),
    tenant_id                text NOT NULL,
    project_id               text NOT NULL,
    name                     text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    head_sequence            bigint NOT NULL DEFAULT 0 CHECK (head_sequence >= 0),
    head_hash                bytea NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
                             CHECK (octet_length(head_hash) = 32),
    head_recorded_at         timestamptz,
    last_checkpoint_sequence bigint NOT NULL DEFAULT 0 CHECK (last_checkpoint_sequence >= 0),
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, name),
    UNIQUE (tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);

CREATE TABLE audit_events (
    id             text PRIMARY KEY CHECK (id ~ '^evt_[0-9A-Z]{26}$'),
    tenant_id      text NOT NULL,
    project_id     text NOT NULL,
    stream_id      text NOT NULL,
    sequence       bigint NOT NULL CHECK (sequence > 0),
    schema_version smallint NOT NULL CHECK (schema_version = 1),
    -- Denormalized index columns. Verification checks them against content.
    actor_type     text NOT NULL,
    actor_id       text NOT NULL,
    action         text NOT NULL,
    resource_type  text,
    resource_id    text,
    occurred_at    timestamptz,
    recorded_at    timestamptz NOT NULL,
    -- The exact RFC 8785 canonical event content that was hashed.
    content        text NOT NULL,
    payload_hash   bytea NOT NULL CHECK (octet_length(payload_hash) = 32),
    previous_hash  bytea NOT NULL CHECK (octet_length(previous_hash) = 32),
    event_hash     bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32),
    signing_key_id text NOT NULL REFERENCES signing_keys (id),
    signature      bytea NOT NULL CHECK (octet_length(signature) = 64),
    UNIQUE (stream_id, sequence),
    FOREIGN KEY (tenant_id, project_id, stream_id) REFERENCES audit_streams (tenant_id, project_id, id)
);
CREATE INDEX audit_events_project_recorded_idx ON audit_events (project_id, recorded_at DESC, id DESC);
CREATE INDEX audit_events_stream_recorded_idx ON audit_events (stream_id, recorded_at);
CREATE INDEX audit_events_actor_idx ON audit_events (project_id, actor_id, recorded_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events (project_id, action text_pattern_ops);
CREATE INDEX audit_events_resource_idx ON audit_events (project_id, resource_type, resource_id, recorded_at DESC);
CREATE INDEX audit_events_signing_key_idx ON audit_events (signing_key_id, recorded_at);

-- ---------------------------------------------------------------------------
-- Checkpoints: signed statements about a stream head.

CREATE TABLE checkpoints (
    id              text PRIMARY KEY CHECK (id ~ '^chk_[0-9A-Z]{26}$'),
    tenant_id       text NOT NULL,
    project_id      text NOT NULL,
    stream_id       text NOT NULL,
    sequence        bigint NOT NULL CHECK (sequence > 0),
    head_hash       bytea NOT NULL CHECK (octet_length(head_hash) = 32),
    created_at      timestamptz NOT NULL,
    checkpoint_hash bytea NOT NULL UNIQUE CHECK (octet_length(checkpoint_hash) = 32),
    signing_key_id  text NOT NULL REFERENCES signing_keys (id),
    signature       bytea NOT NULL CHECK (octet_length(signature) = 64),
    UNIQUE (stream_id, sequence),
    FOREIGN KEY (tenant_id, project_id, stream_id) REFERENCES audit_streams (tenant_id, project_id, id)
);

CREATE TABLE checkpoint_anchors (
    id            text PRIMARY KEY,
    checkpoint_id text NOT NULL REFERENCES checkpoints (id),
    provider      text NOT NULL,
    status        text NOT NULL CHECK (status IN ('anchored', 'failed')),
    receipt       jsonb,
    error         text,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX checkpoint_anchors_checkpoint_idx ON checkpoint_anchors (checkpoint_id);

-- ---------------------------------------------------------------------------
-- Verification history

CREATE TABLE verification_runs (
    id              text PRIMARY KEY CHECK (id ~ '^vrf_[0-9A-Z]{26}$'),
    tenant_id       text NOT NULL,
    project_id      text NOT NULL,
    scope           text NOT NULL CHECK (scope IN ('event', 'stream', 'project')),
    target          text,
    status          text NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'error')),
    trigger         text NOT NULL CHECK (trigger IN ('api', 'dashboard', 'schedule', 'cli', 'system')),
    triggered_by    text,
    streams_checked integer NOT NULL DEFAULT 0,
    events_checked  bigint NOT NULL DEFAULT 0,
    failure_count   integer NOT NULL DEFAULT 0,
    report          jsonb,
    error           text,
    started_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE INDEX verification_runs_project_idx ON verification_runs (project_id, started_at DESC);

CREATE TABLE stream_verifications (
    run_id                 text NOT NULL REFERENCES verification_runs (id) ON DELETE CASCADE,
    stream_id              text NOT NULL REFERENCES audit_streams (id),
    project_id             text NOT NULL REFERENCES projects (id),
    valid                  boolean NOT NULL,
    events_checked         bigint NOT NULL,
    first_sequence         bigint,
    last_sequence          bigint,
    failure_count          integer NOT NULL,
    first_failure_sequence bigint,
    failure_sequences      bigint[] NOT NULL DEFAULT '{}',
    first_failure          jsonb,
    completed_at           timestamptz NOT NULL,
    PRIMARY KEY (run_id, stream_id)
);
CREATE INDEX stream_verifications_latest_idx ON stream_verifications (stream_id, completed_at DESC);

-- ---------------------------------------------------------------------------
-- Evidence exports (job table; packages are stored by the export store)

CREATE TABLE exports (
    id                 text PRIMARY KEY CHECK (id ~ '^exp_[0-9A-Z]{26}$'),
    tenant_id          text NOT NULL,
    project_id         text NOT NULL,
    stream_id          text NOT NULL REFERENCES audit_streams (id),
    status             text NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'expired')),
    params             jsonb NOT NULL,
    created_by         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    started_at         timestamptz,
    completed_at       timestamptz,
    expires_at         timestamptz,
    attempts           integer NOT NULL DEFAULT 0,
    lease_until        timestamptz,
    chain_events       bigint,
    disclosed_events   bigint,
    first_sequence     bigint,
    last_sequence      bigint,
    size_bytes         bigint,
    sha256             bytea,
    manifest_hash      bytea,
    storage_path       text,
    verification_valid boolean,
    error              text,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE INDEX exports_project_idx ON exports (project_id, created_at DESC);
CREATE INDEX exports_queue_idx ON exports (created_at) WHERE status IN ('pending', 'running');

-- ---------------------------------------------------------------------------
-- Idempotency keys for event ingestion

CREATE TABLE idempotency_keys (
    project_id   text NOT NULL REFERENCES projects (id),
    key          text NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    endpoint     text NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    event_ids    text[] NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (project_id, key)
);
CREATE INDEX idempotency_keys_expires_idx ON idempotency_keys (expires_at);

-- ---------------------------------------------------------------------------
-- Guards

CREATE FUNCTION delil_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'DELIL: % on % is not permitted; audit records are append-only', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Altering history is detectable by verification. See docs/security.md for administrative recovery.';
END
$$;

CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER checkpoints_append_only
    BEFORE UPDATE OR DELETE ON checkpoints
    FOR EACH ROW EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER checkpoints_no_truncate
    BEFORE TRUNCATE ON checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER audit_streams_no_delete
    BEFORE DELETE ON audit_streams
    FOR EACH ROW EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER audit_streams_no_truncate
    BEFORE TRUNCATE ON audit_streams
    FOR EACH STATEMENT EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER signing_keys_no_delete
    BEFORE DELETE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION delil_reject_mutation();
CREATE TRIGGER signing_keys_no_truncate
    BEFORE TRUNCATE ON signing_keys
    FOR EACH STATEMENT EXECUTE FUNCTION delil_reject_mutation();

-- Every new event must link to its predecessor in the same stream: contiguous
-- sequence, matching previous_hash, non-decreasing recorded_at.
CREATE FUNCTION delil_check_event_link() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    prev_hash bytea;
    prev_time timestamptz;
BEGIN
    IF NEW.sequence = 1 THEN
        IF NEW.previous_hash <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea THEN
            RAISE EXCEPTION 'DELIL: the first event of stream % must link to the zero hash', NEW.stream_id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    SELECT event_hash, recorded_at INTO prev_hash, prev_time
      FROM audit_events
     WHERE stream_id = NEW.stream_id AND sequence = NEW.sequence - 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'DELIL: sequence % of stream % does not follow an existing event', NEW.sequence, NEW.stream_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF prev_hash <> NEW.previous_hash THEN
        RAISE EXCEPTION 'DELIL: previous_hash of sequence % in stream % does not match its predecessor', NEW.sequence, NEW.stream_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.recorded_at < prev_time THEN
        RAISE EXCEPTION 'DELIL: recorded_at of sequence % in stream % is earlier than its predecessor', NEW.sequence, NEW.stream_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_events_link_check
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION delil_check_event_link();

-- A stream head may only move forward, and only onto an existing event.
CREATE FUNCTION delil_check_stream_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id OR NEW.name <> OLD.name THEN
        RAISE EXCEPTION 'DELIL: stream identity columns are immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.head_sequence < OLD.head_sequence THEN
        RAISE EXCEPTION 'DELIL: stream head cannot move backwards (% -> %)', OLD.head_sequence, NEW.head_sequence
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.head_sequence <> OLD.head_sequence OR NEW.head_hash <> OLD.head_hash THEN
        IF NOT EXISTS (SELECT 1 FROM audit_events
                        WHERE stream_id = NEW.id AND sequence = NEW.head_sequence AND event_hash = NEW.head_hash) THEN
            RAISE EXCEPTION 'DELIL: stream head must point at an existing event' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF NEW.last_checkpoint_sequence < OLD.last_checkpoint_sequence THEN
        RAISE EXCEPTION 'DELIL: checkpoint position cannot move backwards' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_streams_update_guard
    BEFORE UPDATE ON audit_streams
    FOR EACH ROW EXECUTE FUNCTION delil_check_stream_update();

-- A checkpoint must describe an existing event exactly.
CREATE FUNCTION delil_check_checkpoint() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM audit_events
                    WHERE stream_id = NEW.stream_id AND sequence = NEW.sequence AND event_hash = NEW.head_hash) THEN
        RAISE EXCEPTION 'DELIL: checkpoint does not match the event at sequence %', NEW.sequence
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER checkpoints_match_chain
    BEFORE INSERT ON checkpoints
    FOR EACH ROW EXECUTE FUNCTION delil_check_checkpoint();

-- Signing keys: identity and key material are immutable, status only moves
-- forward (active -> retired -> revoked), timestamps are set once. Wrapped
-- private material may be erased (set to NULL) but never replaced.
CREATE FUNCTION delil_check_signing_key_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id
       OR NEW.algorithm <> OLD.algorithm OR NEW.public_key <> OLD.public_key OR NEW.fingerprint <> OLD.fingerprint
       OR NEW.provider <> OLD.provider OR NEW.activated_at <> OLD.activated_at OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'DELIL: signing key identity and material are immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'DELIL: a revoked key cannot be reinstated' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'retired' AND NEW.status = 'active' THEN
        RAISE EXCEPTION 'DELIL: a retired key cannot be reactivated' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
        RAISE EXCEPTION 'DELIL: retired_at cannot be changed once set' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'DELIL: revoked_at cannot be changed once set' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.wrapped_private_key IS NOT NULL AND NEW.wrapped_private_key IS DISTINCT FROM OLD.wrapped_private_key THEN
        RAISE EXCEPTION 'DELIL: wrapped key material can be erased but not replaced' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.provider_ref IS DISTINCT FROM OLD.provider_ref THEN
        RAISE EXCEPTION 'DELIL: provider_ref is immutable' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER signing_keys_update_guard
    BEFORE UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION delil_check_signing_key_update();
