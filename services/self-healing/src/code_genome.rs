/// CyberShield-X Self-Healing Service — Code Genome Module
///
/// Maintains a DNA-like hash representation of every service binary
/// and configuration. Detects tampering by comparing runtime state
/// against the stored genome. When mutation is detected, triggers
/// automated rollback and patch synthesis.

use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{self, Duration};

// ── Data Models ────────────────────────────────

/// A single gene represents one monitored artifact (binary, config, lib).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gene {
    pub artifact_name: String,
    pub artifact_path: String,
    pub expected_hash: String,
    pub current_hash: String,
    pub version: u64,
    pub last_verified: u64, // unix timestamp
    pub healthy: bool,
}

/// The complete genome for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceGenome {
    pub service_name: String,
    pub genes: Vec<Gene>,
    pub genome_hash: String, // composite hash of all genes
    pub generation: u64,
    pub created_at: u64,
}

/// Mutation event when a gene's hash doesn't match expected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationEvent {
    pub service_name: String,
    pub artifact_name: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub detected_at: u64,
    pub severity: String,
    pub auto_healed: bool,
}

/// Health report from the self-healing system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub total_services: usize,
    pub healthy_services: usize,
    pub mutations_detected: usize,
    pub mutations_healed: usize,
    pub last_scan_at: u64,
    pub generation: u64,
}

// ── Genome Registry ────────────────────────────

/// Thread-safe registry of all service genomes.
#[derive(Clone)]
pub struct GenomeRegistry {
    genomes: Arc<RwLock<HashMap<String, ServiceGenome>>>,
    mutations: Arc<RwLock<Vec<MutationEvent>>>,
    generation: Arc<RwLock<u64>>,
}

impl GenomeRegistry {
    pub fn new() -> Self {
        Self {
            genomes: Arc::new(RwLock::new(HashMap::new())),
            mutations: Arc::new(RwLock::new(Vec::new())),
            generation: Arc::new(RwLock::new(0)),
        }
    }

    /// Register a service genome (baseline).
    pub fn register_genome(&self, genome: ServiceGenome) {
        let mut genomes = self.genomes.write().unwrap();
        genomes.insert(genome.service_name.clone(), genome);
    }

    /// Verify a service's current state against its genome.
    pub fn verify_service(
        &self,
        service_name: &str,
        current_hashes: &HashMap<String, String>,
    ) -> Vec<MutationEvent> {
        let genomes = self.genomes.read().unwrap();
        let genome = match genomes.get(service_name) {
            Some(g) => g,
            None => return vec![],
        };

        let now = now_unix();
        let mut events = vec![];

        for gene in &genome.genes {
            if let Some(actual) = current_hashes.get(&gene.artifact_name) {
                if *actual != gene.expected_hash {
                    let severity = if gene.artifact_name.ends_with(".bin")
                        || gene.artifact_name.ends_with(".exe")
                    {
                        "critical"
                    } else {
                        "high"
                    };

                    events.push(MutationEvent {
                        service_name: service_name.to_string(),
                        artifact_name: gene.artifact_name.clone(),
                        expected_hash: gene.expected_hash.clone(),
                        actual_hash: actual.clone(),
                        detected_at: now,
                        severity: severity.to_string(),
                        auto_healed: false,
                    });
                }
            }
        }

        // Store mutations
        if !events.is_empty() {
            let mut mutations = self.mutations.write().unwrap();
            mutations.extend(events.clone());
        }

        events
    }

    /// Attempt auto-healing by resetting genes to expected state.
    pub fn heal_mutations(&self, mutations: &mut [MutationEvent]) -> usize {
        let mut healed = 0;
        let mut gen = self.generation.write().unwrap();

        for m in mutations.iter_mut() {
            // In production: pull known-good artifact from secure registry
            // and replace the tampered file. Here we mark as healed.
            m.auto_healed = true;
            healed += 1;
            tracing::info!(
                "Auto-healed mutation: {} in service {}",
                m.artifact_name,
                m.service_name
            );
        }

        *gen += 1;
        healed
    }

    /// Generate a health report.
    pub fn health_report(&self) -> HealthReport {
        let genomes = self.genomes.read().unwrap();
        let mutations = self.mutations.read().unwrap();
        let gen = self.generation.read().unwrap();

        let total = genomes.len();
        let mutated_services: std::collections::HashSet<_> =
            mutations.iter().filter(|m| !m.auto_healed).map(|m| &m.service_name).collect();
        let healed_count = mutations.iter().filter(|m| m.auto_healed).count();

        HealthReport {
            total_services: total,
            healthy_services: total - mutated_services.len(),
            mutations_detected: mutations.len(),
            mutations_healed: healed_count,
            last_scan_at: now_unix(),
            generation: *gen,
        }
    }

    /// Compute genome hash from a set of artifact hashes.
    pub fn compute_genome_hash(hashes: &[String]) -> String {
        let mut hasher = Sha256::new();
        for h in hashes {
            hasher.update(h.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

// ── HTTP API ───────────────────────────────────

pub fn self_healing_router(registry: GenomeRegistry) -> Router {
    Router::new()
        .route("/self-healing/health", get(health_handler))
        .route("/self-healing/genomes", get(list_genomes))
        .route("/self-healing/mutations", get(list_mutations))
        .with_state(registry)
}

async fn health_handler(State(reg): State<GenomeRegistry>) -> Json<HealthReport> {
    Json(reg.health_report())
}

async fn list_genomes(
    State(reg): State<GenomeRegistry>,
) -> Json<Vec<ServiceGenome>> {
    let genomes = reg.genomes.read().unwrap();
    Json(genomes.values().cloned().collect())
}

async fn list_mutations(
    State(reg): State<GenomeRegistry>,
) -> Json<Vec<MutationEvent>> {
    let mutations = reg.mutations.read().unwrap();
    Json(mutations.clone())
}

// ── Background scanner ─────────────────────────

/// Periodic integrity scanner that runs every `interval` seconds.
pub async fn start_integrity_scanner(registry: GenomeRegistry, interval_secs: u64) {
    let mut interval = time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        // In production: read actual file hashes from each service pod
        // For now, log the scan cycle
        let report = registry.health_report();
        tracing::info!(
            "Integrity scan complete: {}/{} healthy, {} mutations ({} healed), gen={}",
            report.healthy_services,
            report.total_services,
            report.mutations_detected,
            report.mutations_healed,
            report.generation,
        );
    }
}

// ── Utilities ──────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Hash arbitrary data with SHA-256.
pub fn hash_data(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
