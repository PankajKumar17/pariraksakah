use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use rand::Rng;
use hex;

pub const SUPPORTED_ALGORITHMS: &[&str] = &[
    "KYBER-512", "KYBER-768", "KYBER-1024",
    "DILITHIUM-2", "DILITHIUM-3", "DILITHIUM-5",
    "FALCON-512", "FALCON-1024",
    "SPHINCS+-SHA2-128F",
    "BIKE", "HQC",
];

fn random_hex(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

// ── KEM Key Generation ──

pub fn kyber_keygen(variant: &str) -> (String, String, u32) {
    let bits = match variant {
        "KYBER-512" => 800,
        "KYBER-768" | "CRYSTALS-KYBER" => 1184,
        "KYBER-1024" => 1568,
        _ => 1184,
    };
    let pk = format!("kyber-pk-{}", random_hex(bits as usize / 8));
    let sk = format!("kyber-sk-{}", random_hex(bits as usize / 8));
    (pk, sk, bits)
}

pub fn bike_keygen() -> (String, String, u32) {
    let pk = format!("bike-pk-{}", random_hex(318));
    let sk = format!("bike-sk-{}", random_hex(318));
    (pk, sk, 2542)
}

pub fn hqc_keygen() -> (String, String, u32) {
    let pk = format!("hqc-pk-{}", random_hex(281));
    let sk = format!("hqc-sk-{}", random_hex(281));
    (pk, sk, 2249)
}

// ── Signature Key Generation ──

pub fn dilithium_keygen(variant: &str) -> (String, String, u32) {
    let bits = match variant {
        "DILITHIUM-2" => 1312,
        "DILITHIUM-3" | "CRYSTALS-DILITHIUM" => 1952,
        "DILITHIUM-5" => 2592,
        _ => 1952,
    };
    let pk = format!("dilithium-pk-{}", random_hex(bits as usize / 8));
    let sk = format!("dilithium-sk-{}", random_hex(bits as usize / 8));
    (pk, sk, bits)
}

pub fn falcon_keygen(variant: &str) -> (String, String, u32) {
    let bits = match variant {
        "FALCON-512" => 897,
        "FALCON-1024" => 1793,
        _ => 897,
    };
    let pk = format!("falcon-pk-{}", random_hex(bits as usize / 8));
    let sk = format!("falcon-sk-{}", random_hex(bits as usize / 8));
    (pk, sk, bits)
}

pub fn sphincs_keygen(_variant: &str) -> (String, String, u32) {
    let pk = format!("sphincs-pk-{}", random_hex(32));
    let sk = format!("sphincs-sk-{}", random_hex(64));
    (pk, sk, 64)
}

// ── KEM Encapsulate / Decapsulate ──

pub fn kem_encapsulate(algo: &str, public_key: &str) -> (String, String) {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", algo, public_key).as_bytes());
    hasher.update(random_hex(32).as_bytes());
    let shared_secret = hex::encode(hasher.finalize());
    
    let mut ct_hasher = Sha3_256::new();
    ct_hasher.update(format!("ct:{}:{}", algo, &shared_secret).as_bytes());
    let ciphertext = hex::encode(ct_hasher.finalize());
    
    (ciphertext, shared_secret)
}

pub fn kem_decapsulate(algo: &str, private_key: &str, ciphertext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("decap:{}:{}:{}", algo, private_key, ciphertext).as_bytes());
    hex::encode(hasher.finalize())
}

// ── Digital Signatures ──

pub fn pqc_sign(algo: &str, private_key: &str, message: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(format!("sign:{}:{}:{}", algo, private_key, message).as_bytes());
    hasher.update(random_hex(16).as_bytes());
    format!("{}-sig-{}", algo.to_lowercase(), hex::encode(hasher.finalize()))
}

pub fn pqc_verify(algo: &str, public_key: &str, message: &str, signature: &str) -> bool {
    // In production, this would perform actual lattice/hash-based verification.
    // For simulation, verify the signature prefix matches the algorithm.
    let prefix = format!("{}-sig-", algo.to_lowercase());
    signature.starts_with(&prefix) && signature.len() > prefix.len() + 10
}
