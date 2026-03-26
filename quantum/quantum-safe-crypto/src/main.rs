use actix_web::{web, App, HttpServer, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Sha3_512;
use rand::Rng;
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::Mutex;

mod pqc_algorithms;
use pqc_algorithms::*;

// ── Data Models ──

#[derive(Serialize, Deserialize, Clone)]
struct KeyPair {
    key_id: String,
    algorithm: String,
    public_key: String,
    private_key: String,
    key_size_bits: u32,
    created_at: String,
}

#[derive(Deserialize)]
struct KeygenRequest {
    algorithm: String,
    #[serde(default = "default_level")]
    security_level: u32,
}
fn default_level() -> u32 { 3 }

#[derive(Deserialize)]
struct EncapsulateRequest {
    algorithm: String,
    public_key: String,
}

#[derive(Deserialize)]
struct DecapsulateRequest {
    algorithm: String,
    private_key: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct SignRequest {
    algorithm: String,
    private_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    algorithm: String,
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct AlgorithmInfo {
    name: String,
    category: String,
    nist_level: u32,
    key_size_bits: u32,
    signature_size_bytes: Option<u32>,
    ciphertext_size_bytes: Option<u32>,
    quantum_safe: bool,
}

struct AppState {
    keys: Mutex<HashMap<String, KeyPair>>,
}

// ── Handlers ──

async fn keygen(data: web::Data<AppState>, req: web::Json<KeygenRequest>) -> HttpResponse {
    let algo = req.algorithm.to_uppercase();
    let (pk, sk, bits) = match algo.as_str() {
        "KYBER-512" | "KYBER-768" | "KYBER-1024" | "CRYSTALS-KYBER" => {
            kyber_keygen(&algo)
        },
        "DILITHIUM-2" | "DILITHIUM-3" | "DILITHIUM-5" | "CRYSTALS-DILITHIUM" => {
            dilithium_keygen(&algo)
        },
        "FALCON-512" | "FALCON-1024" => {
            falcon_keygen(&algo)
        },
        "SPHINCS+-SHA2-128F" | "SPHINCS+" => {
            sphincs_keygen(&algo)
        },
        "BIKE" => {
            bike_keygen()
        },
        "HQC" => {
            hqc_keygen()
        },
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Unsupported algorithm", "supported": SUPPORTED_ALGORITHMS}));
        }
    };

    let key_id = Uuid::new_v4().to_string();
    let kp = KeyPair {
        key_id: key_id.clone(),
        algorithm: algo.clone(),
        public_key: pk,
        private_key: sk,
        key_size_bits: bits,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    data.keys.lock().unwrap().insert(key_id.clone(), kp.clone());

    HttpResponse::Ok().json(serde_json::json!({
        "key_id": key_id,
        "algorithm": algo,
        "public_key": kp.public_key,
        "private_key": kp.private_key,
        "key_size_bits": bits
    }))
}

async fn encapsulate(req: web::Json<EncapsulateRequest>) -> HttpResponse {
    let algo = req.algorithm.to_uppercase();
    let (ciphertext, shared_secret) = match algo.as_str() {
        "KYBER-512" | "KYBER-768" | "KYBER-1024" | "CRYSTALS-KYBER" => {
            kem_encapsulate(&algo, &req.public_key)
        },
        "BIKE" => kem_encapsulate("BIKE", &req.public_key),
        "HQC" => kem_encapsulate("HQC", &req.public_key),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Not a KEM algorithm"})),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "ciphertext": ciphertext,
        "shared_secret": shared_secret,
        "algorithm": algo
    }))
}

async fn decapsulate(req: web::Json<DecapsulateRequest>) -> HttpResponse {
    let algo = req.algorithm.to_uppercase();
    let shared_secret = kem_decapsulate(&algo, &req.private_key, &req.ciphertext);

    HttpResponse::Ok().json(serde_json::json!({
        "shared_secret": shared_secret,
        "algorithm": algo
    }))
}

async fn sign(req: web::Json<SignRequest>) -> HttpResponse {
    let algo = req.algorithm.to_uppercase();
    let signature = match algo.as_str() {
        "DILITHIUM-2" | "DILITHIUM-3" | "DILITHIUM-5" | "CRYSTALS-DILITHIUM" => {
            pqc_sign(&algo, &req.private_key, &req.message)
        },
        "FALCON-512" | "FALCON-1024" => {
            pqc_sign(&algo, &req.private_key, &req.message)
        },
        "SPHINCS+-SHA2-128F" | "SPHINCS+" => {
            pqc_sign(&algo, &req.private_key, &req.message)
        },
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Not a signature algorithm"})),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "signature": signature,
        "algorithm": algo
    }))
}

async fn verify(req: web::Json<VerifyRequest>) -> HttpResponse {
    let algo = req.algorithm.to_uppercase();
    let valid = pqc_verify(&algo, &req.public_key, &req.message, &req.signature);

    HttpResponse::Ok().json(serde_json::json!({
        "valid": valid,
        "algorithm": algo
    }))
}

async fn list_algorithms() -> HttpResponse {
    let algos = vec![
        AlgorithmInfo { name: "CRYSTALS-Kyber-512".into(), category: "KEM".into(), nist_level: 1, key_size_bits: 800, signature_size_bytes: None, ciphertext_size_bytes: Some(768), quantum_safe: true },
        AlgorithmInfo { name: "CRYSTALS-Kyber-768".into(), category: "KEM".into(), nist_level: 3, key_size_bits: 1184, signature_size_bytes: None, ciphertext_size_bytes: Some(1088), quantum_safe: true },
        AlgorithmInfo { name: "CRYSTALS-Kyber-1024".into(), category: "KEM".into(), nist_level: 5, key_size_bits: 1568, signature_size_bytes: None, ciphertext_size_bytes: Some(1568), quantum_safe: true },
        AlgorithmInfo { name: "BIKE".into(), category: "KEM".into(), nist_level: 1, key_size_bits: 2542, signature_size_bytes: None, ciphertext_size_bytes: Some(2542), quantum_safe: true },
        AlgorithmInfo { name: "HQC".into(), category: "KEM".into(), nist_level: 1, key_size_bits: 2249, signature_size_bytes: None, ciphertext_size_bytes: Some(4481), quantum_safe: true },
        AlgorithmInfo { name: "CRYSTALS-Dilithium-2".into(), category: "Signature".into(), nist_level: 2, key_size_bits: 1312, signature_size_bytes: Some(2420), ciphertext_size_bytes: None, quantum_safe: true },
        AlgorithmInfo { name: "CRYSTALS-Dilithium-3".into(), category: "Signature".into(), nist_level: 3, key_size_bits: 1952, signature_size_bytes: Some(3293), ciphertext_size_bytes: None, quantum_safe: true },
        AlgorithmInfo { name: "CRYSTALS-Dilithium-5".into(), category: "Signature".into(), nist_level: 5, key_size_bits: 2592, signature_size_bytes: Some(4595), ciphertext_size_bytes: None, quantum_safe: true },
        AlgorithmInfo { name: "FALCON-512".into(), category: "Signature".into(), nist_level: 1, key_size_bits: 897, signature_size_bytes: Some(666), ciphertext_size_bytes: None, quantum_safe: true },
        AlgorithmInfo { name: "FALCON-1024".into(), category: "Signature".into(), nist_level: 5, key_size_bits: 1793, signature_size_bytes: Some(1280), ciphertext_size_bytes: None, quantum_safe: true },
        AlgorithmInfo { name: "SPHINCS+-SHA2-128f".into(), category: "Signature".into(), nist_level: 1, key_size_bits: 64, signature_size_bytes: Some(17088), ciphertext_size_bytes: None, quantum_safe: true },
    ];
    HttpResponse::Ok().json(algos)
}

async fn recommend(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let use_case = query.get("use_case").map(|s| s.as_str()).unwrap_or("general");
    let rec = match use_case {
        "key_exchange" | "kem" => serde_json::json!({"recommended": "CRYSTALS-Kyber-1024", "reason": "NIST Level 5, fastest KEM"}),
        "signature" | "signing" => serde_json::json!({"recommended": "FALCON-512", "reason": "Smallest signature size (666 bytes)"}),
        "stateless_signature" => serde_json::json!({"recommended": "SPHINCS+-SHA2-128f", "reason": "Stateless, no key state management needed"}),
        "high_security" => serde_json::json!({"recommended": "CRYSTALS-Dilithium-5", "reason": "NIST Level 5 signature"}),
        "diversity" => serde_json::json!({"recommended": "HQC", "reason": "Code-based alternative to lattice-based Kyber"}),
        _ => serde_json::json!({"recommended": "CRYSTALS-Kyber-1024", "reason": "Default: strongest NIST-standardized KEM"}),
    };
    HttpResponse::Ok().json(rec)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "quantum-crypto-engine"}))
}

async fn metrics() -> HttpResponse {
    HttpResponse::Ok().body("# Quantum Crypto Engine Metrics\nquantum_keys_generated 0\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("QUANTUM_CRYPTO_PORT").unwrap_or_else(|_| "8080".into()).parse().unwrap_or(8080);

    let data = web::Data::new(AppState {
        keys: Mutex::new(HashMap::new()),
    });

    println!("Quantum Crypto Engine starting on port {}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/quantum/crypto/keygen", web::post().to(keygen))
            .route("/quantum/crypto/encapsulate", web::post().to(encapsulate))
            .route("/quantum/crypto/decapsulate", web::post().to(decapsulate))
            .route("/quantum/crypto/sign", web::post().to(sign))
            .route("/quantum/crypto/verify", web::post().to(verify))
            .route("/quantum/crypto/algorithms", web::get().to(list_algorithms))
            .route("/quantum/crypto/recommend", web::get().to(recommend))
            .route("/health", web::get().to(health))
            .route("/metrics", web::get().to(metrics))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
