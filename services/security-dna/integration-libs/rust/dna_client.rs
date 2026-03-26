use reqwest;
use serde_json::Value;

pub async fn verify_trust(caller_dna_id: &str, target_id: &str) -> bool {
    // Requires DNA Trust Registry
    let trust_url = std::env::var("DNA_TRUST_REGISTRY_URL")
        .unwrap_or_else(|_| "http://dna-trust-registry:8053".to_string());

    let url = format!("{}/trust/verify/{}/{}", trust_url, caller_dna_id, target_id);
    
    let client = reqwest::Client::new();
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(allowed) = json.get("allowed") {
                    if allowed.as_bool() == Some(true) {
                        return true;
                    }
                }
            }
        }
    }
    // Block action if unable to verify trust
    false
}
