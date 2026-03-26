-- TimescaleDB Schemas for Security DNA Cryptographic System Identity Platform

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS component_identities (
    id TEXT PRIMARY KEY,
    component_name TEXT NOT NULL,
    component_type TEXT NOT NULL,
    dna_fingerprint TEXT NOT NULL,
    public_key TEXT NOT NULL,
    certificate_serial TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    trust_score DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS identity_verifications (
    id TEXT PRIMARY KEY,
    component_id TEXT NOT NULL REFERENCES component_identities(id),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verification_method TEXT NOT NULL,
    result BOOLEAN NOT NULL,
    anomaly_score DOUBLE PRECISION,
    verifier_id TEXT NOT NULL REFERENCES component_identities(id)
);
SELECT create_hypertable('identity_verifications', 'verified_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS fingerprint_history (
    id TEXT PRIMARY KEY,
    component_id TEXT NOT NULL REFERENCES component_identities(id),
    fingerprint_hash TEXT NOT NULL,
    behavioral_hash TEXT NOT NULL,
    hardware_hash TEXT NOT NULL,
    network_hash TEXT NOT NULL,
    temporal_hash TEXT NOT NULL,
    software_hash TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delta_score DOUBLE PRECISION NOT NULL
);
SELECT create_hypertable('fingerprint_history', 'recorded_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS trust_score_history (
    id TEXT PRIMARY KEY,
    component_id TEXT NOT NULL REFERENCES component_identities(id),
    trust_score DOUBLE PRECISION NOT NULL,
    contributing_factors JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('trust_score_history', 'recorded_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS dna_audit_trail (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    component_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    outcome TEXT NOT NULL,
    signature TEXT NOT NULL
);
SELECT create_hypertable('dna_audit_trail', 'timestamp', if_not_exists => TRUE);

-- Make dna_audit_trail immutable / append-only using a trigger
CREATE OR REPLACE FUNCTION audit_trail_insert_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'dna_audit_trail is immutable. Updates and Deletes are forbidden.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_trail_immutable_upd ON dna_audit_trail;
CREATE TRIGGER trg_audit_trail_immutable_upd
BEFORE UPDATE OR DELETE ON dna_audit_trail
FOR EACH ROW EXECUTE PROCEDURE audit_trail_insert_only();
