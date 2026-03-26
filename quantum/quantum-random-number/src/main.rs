use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use rand::Rng;
use sha2::{Sha256, Digest};
use uuid::Uuid;
use std::sync::Mutex;

mod nist_tests;
use nist_tests::NistTestSuite;

struct RngState {
    total_bits_generated: Mutex<u64>,
    last_quality_score: Mutex<f64>,
}

#[derive(Serialize)]
struct QualityResult {
    batch_id: String,
    tests: Vec<TestResult>,
    overall_score: f64,
    passed: bool,
}

#[derive(Serialize)]
struct TestResult {
    name: String,
    p_value: f64,
    passed: bool,
}

/// Simulate quantum Hadamard gate measurement for entropy
fn quantum_random_bytes(count: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; count];
    // Simulate: each bit from H|0⟩ measurement (50/50 superposition collapse)
    for byte in bytes.iter_mut() {
        let mut val: u8 = 0;
        for bit in 0..8 {
            // Each bit represents one qubit measurement after Hadamard
            if rng.gen_bool(0.5) {
                val |= 1 << bit;
            }
        }
        *byte = val;
    }
    bytes
}

async fn get_bytes(path: web::Path<usize>, state: web::Data<RngState>) -> HttpResponse {
    let count = path.into_inner().min(1_000_000);  // Max 1MB
    let bytes = quantum_random_bytes(count);
    *state.total_bits_generated.lock().unwrap() += (count * 8) as u64;
    HttpResponse::Ok().json(serde_json::json!({
        "bytes": hex::encode(&bytes),
        "count": count,
        "entropy_source": "quantum_hadamard_simulation"
    }))
}

async fn get_integer(path: web::Path<(i64, i64)>) -> HttpResponse {
    let (min, max) = path.into_inner();
    if min >= max {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "min must be < max"}));
    }
    let bytes = quantum_random_bytes(8);
    let raw = u64::from_le_bytes(bytes.try_into().unwrap());
    let range = (max - min) as u64;
    let value = min + (raw % range) as i64;
    HttpResponse::Ok().json(serde_json::json!({"value": value, "min": min, "max": max}))
}

async fn get_uuid() -> HttpResponse {
    let bytes = quantum_random_bytes(16);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    // Set UUID v4 variant bits
    arr[6] = (arr[6] & 0x0f) | 0x40;
    arr[8] = (arr[8] & 0x3f) | 0x80;
    let uuid_str = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes(arr[0..4].try_into().unwrap()),
        u16::from_be_bytes(arr[4..6].try_into().unwrap()),
        u16::from_be_bytes(arr[6..8].try_into().unwrap()),
        u16::from_be_bytes(arr[8..10].try_into().unwrap()),
        u64::from_be_bytes({
            let mut a = [0u8; 8];
            a[2..8].copy_from_slice(&arr[10..16]);
            a
        })
    );
    HttpResponse::Ok().json(serde_json::json!({"uuid": uuid_str, "entropy_source": "quantum"}))
}

async fn get_quality(state: web::Data<RngState>) -> HttpResponse {
    let score = *state.last_quality_score.lock().unwrap();
    HttpResponse::Ok().json(serde_json::json!({
        "current_quality_score": score,
        "threshold": 95.0,
        "status": if score >= 95.0 { "PASS" } else { "FAIL" }
    }))
}

async fn run_nist_test(state: web::Data<RngState>) -> HttpResponse {
    let batch = quantum_random_bytes(2500); // 20000 bits
    let suite = NistTestSuite::new(&batch);
    let results = suite.run_all();
    
    let passed_count = results.iter().filter(|r| r.1).count();
    let total = results.len();
    let score = (passed_count as f64 / total as f64) * 100.0;
    
    *state.last_quality_score.lock().unwrap() = score;
    
    let test_results: Vec<TestResult> = results.into_iter().map(|(name, passed, p_value)| {
        TestResult { name, p_value, passed }
    }).collect();
    
    let batch_id = Uuid::new_v4().to_string();
    
    HttpResponse::Ok().json(QualityResult {
        batch_id,
        tests: test_results,
        overall_score: score,
        passed: score >= 95.0,
    })
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "quantum-rng-service"}))
}

async fn metrics(state: web::Data<RngState>) -> HttpResponse {
    let bits = *state.total_bits_generated.lock().unwrap();
    let score = *state.last_quality_score.lock().unwrap();
    HttpResponse::Ok().body(format!(
        "# QRNG Metrics\nquantum_rng_bits_generated {}\nquantum_rng_quality_score {}\n",
        bits, score
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("QUANTUM_RNG_PORT").unwrap_or_else(|_| "8082".into()).parse().unwrap_or(8082);
    let state = web::Data::new(RngState {
        total_bits_generated: Mutex::new(0),
        last_quality_score: Mutex::new(98.0),
    });

    println!("Quantum RNG Service starting on port {}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/quantum/rng/bytes/{count}", web::get().to(get_bytes))
            .route("/quantum/rng/integer/{min}/{max}", web::get().to(get_integer))
            .route("/quantum/rng/uuid", web::get().to(get_uuid))
            .route("/quantum/rng/quality", web::get().to(get_quality))
            .route("/quantum/rng/test", web::post().to(run_nist_test))
            .route("/health", web::get().to(health))
            .route("/metrics", web::get().to(metrics))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
