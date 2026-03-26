# Test and Validation Plan: Security DNA Cryptographic Platform

## 1. Unit Tests

### 1.1 DNA Identity Engine (Rust)
- **`test_hardware_fingerprint_stability`**: Verify `collect_hardware_fingerprint()` returns identical SHA-256 hashes on consecutive runs within a 1-second interval without system modifications.
- **`test_fingerprint_fusion`**: Validate that the BLAKE3 fusion of the 5 layers operates deterministically mapping 5 unique strings to one 256-bit hexadecimal output.
- **`test_crystals_dilithium_signing`**: Generate a PQC keypair. Sign the fused DNA blob. Verify the signature successfully against the generated public key.

### 1.2 Internal Certificate Authority (Go)
- **`test_cert_issuance_validity`**: POST `/ca/issue/test_comp`. Check if the returned X.509 representation contains the `DNAFingerprint` custom extension and `IssuedAt` / `ExpiresAt` correctly set (delta of 365 days).
- **`test_cert_revocation`**: POST `/ca/revoke/test_comp`. Verify that a subsequent call to GET `/ca/ocsp/:serial` for that component returns `REVOKED` and the revocation event was produced to Kafka `dna.identity.revoked`.

### 1.3 Trust Registry (Go)
- **`test_trust_score_calculation`**: Provide mocked inputs of 100% certificate validity, 0 delta fingerprint changes, 0 behavioral anomalies. Assert the final ITCS is precisely 100.
- **`test_manual_override`**: Admin calls POST `/trust/override/api-gateway` with score `0.0`. Verify that subsequent inter-service verification (`GET /trust/verify/api-gateway/redis`) explicitly returns `HTTP 403 Forbidden` (`allowed: false`).

## 2. Integration Tests

### 2.1 Kafka Message Flow Authentication
- **Test**: Have `Component A` send an Avro message to `dna.identity.issued` with a valid Dilithium signature in the headers. Ensure the Schema Registry validates the message against the `.avsc` and consumer processes it.
- **Test**: Dispatch a message with a flipped byte in the signature payload and verify it is correctly rejected by consumers.

### 2.2 End-to-End Identity Lifecycle
1. Register new component `neo4j-replica` via `dna-identity-engine`.
2. Grab the generated DNA and auto-issue a Certificate via `dna-certificate-authority`.
3. Verify the certificate OCSP status is `ACTIVE`.
4. Run `dna-fingerprint-monitor` to fetch its baseline.
5. Simulate manual anomaly via Trust Registry override to score = 20.0.
6. Check `dna-anomaly-detector` publishes anomaly event and verifies certificate is marked `REVOKED`.

## 3. Security & Spoofing Simulation Tests

### 3.1 Component Spoofing (Impersonation Attempt)
- **Scenario**: Start an attacker Python container using the `--net=host` but varying `/proc/cpuinfo` and `cgroup` hashes to spoof `api-gateway`.
- **Expected Outcome**: `dna-identity-engine` calculates a differing hardware hash and rejects identity verification. `dna-anomaly-detector` creates an `ImpersonationAttempt` Neo4j node.

### 3.2 Certificate Cloning
- **Scenario**: Legitimate container `A` operates normally. Container `B` (Attacker) copies the certificate file from `A` and tries to communicate with `redis`.
- **Expected Outcome**: The `dna_middleware.go` intercepts the call, fetches the living DNA identity of `B`, matches against the mapped serial in TimescaleDB, detects a fingerprint mismatch `delta > 50%`, drops the packet, and alerts `dna.anomaly.detected`.

## 4. Performance Benchmarks

### 4.1 Zero-Trust Latency Verification
- **Test**: Stress test the GET `/trust/verify/:caller/:target` endpoint using `wrk` with 1,000 requests per second.
- **Passing Criteria**: P95 latency must remain under 10 milliseconds, adhering to intra-mesh performance bounds, proving local memory-caching of trust scores is functioning over continuous DB polls.
