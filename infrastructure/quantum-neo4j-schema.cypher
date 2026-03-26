// Quantum Security Suite: Neo4j Graph Schema

// ── Node Constraints ──
CREATE CONSTRAINT quantum_key_unique IF NOT EXISTS FOR (k:QuantumKeyNode) REQUIRE k.key_id IS UNIQUE;
CREATE CONSTRAINT supply_chain_unique IF NOT EXISTS FOR (s:SupplyChainNode) REQUIRE s.artifact_id IS UNIQUE;
CREATE CONSTRAINT quantum_trust_unique IF NOT EXISTS FOR (t:QuantumTrustNode) REQUIRE t.verification_id IS UNIQUE;
CREATE CONSTRAINT attack_scenario_unique IF NOT EXISTS FOR (a:AttackScenarioNode) REQUIRE a.simulation_id IS UNIQUE;

// ── Indexes ──
CREATE INDEX quantum_key_algo IF NOT EXISTS FOR (k:QuantumKeyNode) ON (k.algorithm);
CREATE INDEX supply_chain_type IF NOT EXISTS FOR (s:SupplyChainNode) ON (s.type);
CREATE INDEX quantum_trust_score IF NOT EXISTS FOR (t:QuantumTrustNode) ON (t.trust_score);
CREATE INDEX attack_type IF NOT EXISTS FOR (a:AttackScenarioNode) ON (a.attack_type);

// ── Sample Schema Nodes ──

// QuantumKeyNode
MERGE (k:QuantumKeyNode {key_id: "schema-template"})
SET k.algorithm = "CRYSTALS-Kyber-1024",
    k.strength = "AES-256 equivalent",
    k.status = "template",
    k.key_size_bits = 1024,
    k.generation_method = "QRNG";

// SupplyChainNode
MERGE (s:SupplyChainNode {artifact_id: "schema-template"})
SET s.type = "container-image",
    s.hash = "sha256:template",
    s.verified = false,
    s.signature_algorithm = "SPHINCS+-SHA2-128f";

// QuantumTrustNode
MERGE (t:QuantumTrustNode {verification_id: "schema-template"})
SET t.trust_score = 0.0,
    t.quantum_signed = true,
    t.subject_id = "template",
    t.resource_id = "template";

// AttackScenarioNode
MERGE (a:AttackScenarioNode {simulation_id: "schema-template"})
SET a.attack_type = "shor",
    a.target_crypto = "RSA-2048",
    a.success_probability = 0.0,
    a.qubits_required = 4099;

// ── Relationship Types ──

// QKDChannelEdge: connects QuantumKeyNodes that share a QKD channel
// Properties: protocol, qber_rate, secure
// Example: (k1:QuantumKeyNode)-[:QKD_CHANNEL {protocol: "BB84", qber_rate: 0.03, secure: true}]->(k2:QuantumKeyNode)

// MitigationEdge: connects AttackScenarioNode to recommended algorithm
// Properties: recommended_algorithm, strength_improvement
// Example: (a:AttackScenarioNode)-[:MITIGATES {recommended_algorithm: "Kyber-1024", strength_improvement: "quantum-safe"}]->(k:QuantumKeyNode)

// VERIFIES: connects SupplyChainNode to the quantum key used for verification
// Example: (s:SupplyChainNode)-[:VERIFIED_BY]->(k:QuantumKeyNode)

// TRUSTS: connects QuantumTrustNode to subjects and resources
// Example: (t:QuantumTrustNode)-[:TRUSTS {decision: "allow"}]->(resource:QuantumTrustNode)

// Cleanup template nodes
MATCH (n) WHERE n.key_id = "schema-template" OR n.artifact_id = "schema-template"
  OR n.verification_id = "schema-template" OR n.simulation_id = "schema-template"
DELETE n;
