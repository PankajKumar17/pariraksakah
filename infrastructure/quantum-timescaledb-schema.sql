-- Quantum Security Suite: TimescaleDB Schema
-- Run against the existing TimescaleDB instance

CREATE TABLE IF NOT EXISTS quantum_key_inventory (
    id              BIGSERIAL,
    key_id          TEXT NOT NULL UNIQUE,
    algorithm       TEXT NOT NULL,
    key_size_bits   INT NOT NULL,
    generation_method TEXT NOT NULL,
    entropy_source  TEXT NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    usage_count     INT DEFAULT 0,
    status          TEXT DEFAULT 'active'
);
SELECT create_hypertable('quantum_key_inventory', 'generated_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS qkd_sessions (
    id                BIGSERIAL,
    session_id        TEXT NOT NULL UNIQUE,
    alice_endpoint    TEXT NOT NULL,
    bob_endpoint      TEXT NOT NULL,
    protocol          TEXT NOT NULL,
    qber_rate         DOUBLE PRECISION DEFAULT 0.0,
    key_bits_generated INT DEFAULT 0,
    eavesdrop_detected BOOLEAN DEFAULT FALSE,
    session_start     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_end       TIMESTAMPTZ
);
SELECT create_hypertable('qkd_sessions', 'session_start', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS rng_generation_log (
    id              BIGSERIAL,
    batch_id        TEXT NOT NULL,
    entropy_source  TEXT NOT NULL,
    bits_generated  INT NOT NULL,
    nist_test_suite_results JSONB,
    randomness_score DOUBLE PRECISION DEFAULT 0.0,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('rng_generation_log', 'generated_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS quantum_threat_detections (
    id                        BIGSERIAL,
    detection_id              TEXT NOT NULL,
    threat_type               TEXT NOT NULL,
    quantum_algorithm_used    TEXT NOT NULL,
    classical_comparison_score DOUBLE PRECISION DEFAULT 0.0,
    quantum_confidence_score  DOUBLE PRECISION DEFAULT 0.0,
    speed_improvement_factor  DOUBLE PRECISION DEFAULT 1.0,
    detected_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('quantum_threat_detections', 'detected_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS quantum_ml_results (
    id                      BIGSERIAL,
    model_id                TEXT NOT NULL,
    circuit_depth           INT DEFAULT 0,
    qubit_count             INT DEFAULT 0,
    anomaly_score           DOUBLE PRECISION DEFAULT 0.0,
    classical_baseline_score DOUBLE PRECISION DEFAULT 0.0,
    quantum_advantage_ratio DOUBLE PRECISION DEFAULT 1.0,
    inference_time_ms       DOUBLE PRECISION DEFAULT 0.0,
    recorded_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('quantum_ml_results', 'recorded_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS supply_chain_verifications (
    id                  BIGSERIAL,
    artifact_id         TEXT NOT NULL,
    artifact_type       TEXT NOT NULL,
    artifact_hash       TEXT NOT NULL,
    quantum_signature   TEXT,
    verification_result TEXT DEFAULT 'pending',
    tamper_detected     BOOLEAN DEFAULT FALSE,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('supply_chain_verifications', 'verified_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS attack_simulations (
    id                      BIGSERIAL,
    simulation_id           TEXT NOT NULL,
    attack_type             TEXT NOT NULL,
    quantum_algorithm       TEXT NOT NULL,
    target_crypto           TEXT NOT NULL,
    success_probability     DOUBLE PRECISION DEFAULT 0.0,
    time_to_break_estimate  TEXT,
    mitigation_recommended  TEXT,
    simulated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('attack_simulations', 'simulated_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS zero_trust_verifications (
    id                  BIGSERIAL,
    verification_id     TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    resource_id         TEXT NOT NULL,
    quantum_entropy_used BOOLEAN DEFAULT FALSE,
    trust_score         DOUBLE PRECISION DEFAULT 0.0,
    decision            TEXT DEFAULT 'deny',
    quantum_signature   TEXT,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('zero_trust_verifications', 'verified_at', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS quantum_audit_trail (
    id                BIGSERIAL,
    action            TEXT NOT NULL,
    quantum_service   TEXT NOT NULL,
    component         TEXT NOT NULL,
    timestamp         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    outcome           TEXT NOT NULL,
    quantum_signature TEXT
);
SELECT create_hypertable('quantum_audit_trail', 'timestamp', if_not_exists => TRUE);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_qki_algorithm ON quantum_key_inventory (algorithm);
CREATE INDEX IF NOT EXISTS idx_qki_status ON quantum_key_inventory (status);
CREATE INDEX IF NOT EXISTS idx_qkd_protocol ON qkd_sessions (protocol);
CREATE INDEX IF NOT EXISTS idx_qtd_threat_type ON quantum_threat_detections (threat_type);
CREATE INDEX IF NOT EXISTS idx_scv_artifact_type ON supply_chain_verifications (artifact_type);
CREATE INDEX IF NOT EXISTS idx_ztv_subject ON zero_trust_verifications (subject_id);
CREATE INDEX IF NOT EXISTS idx_qat_service ON quantum_audit_trail (quantum_service);
