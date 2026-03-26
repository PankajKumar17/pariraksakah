package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

func getQuantumReadinessHandler(w http.ResponseWriter, r *http.Request) {
	// Aggregate readiness across 8 quantum capability areas
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"overall_score": 88,
		"crypto_agility": 95,
		"qkd_readiness": 80,
		"rng_entropy": 100,
		"threat_detection": 90,
		"ml_anomaly": 85,
		"supply_chain": 92,
		"attack_simulation": 88,
		"zero_trust": 75,
	})
}

func getCryptoInventoryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{
		{"target": "API_Gateway_TLS", "algorithm": "RSA-2048", "quantum_safe": false, "status": "vulnerable", "urgency_score": 9.5},
		{"target": "Service_Mesh_mTLS", "algorithm": "CRYSTALS-Kyber-1024", "quantum_safe": true, "status": "migrated", "urgency_score": 0.0},
		{"target": "Audit_Logs", "algorithm": "CRYSTALS-Dilithium-5", "quantum_safe": true, "status": "migrated", "urgency_score": 0.0},
		{"target": "Database_Encryption", "algorithm": "AES-256-GCM", "quantum_safe": true, "status": "safe", "urgency_score": 2.0},
		{"target": "Legacy_Tokens", "algorithm": "ECDSA-P256", "quantum_safe": false, "status": "vulnerable", "urgency_score": 8.5},
	})
}

func getMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"qkd": map[string]interface{}{
			"active_sessions": 12,
			"average_qber": 0.035,
			"key_bits_available": 1048576,
			"eavesdrops_detected": 2,
		},
		"qrng": map[string]interface{}{
			"quality_score": 99.8,
			"bits_generated_24h": 5000000000,
			"nist_tests_passing": 15, // out of 15
		},
		"qml": map[string]interface{}{
			"average_quantum_advantage": 1.28,
			"anomalies_detected": 47,
		},
		"supply_chain": map[string]interface{}{
			"merkle_root": "5f1b...8e2a",
			"verified_artifacts": 156,
			"violations_detected": 0,
		},
		"zero_trust": map[string]interface{}{
			"verifications_24h": 45000,
			"denials": 1240,
			"quantum_entropy_calls": 45000,
		},
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy","service":"quantum-dashboard-api"}`))
}

func main() {
	port := os.Getenv("QUANTUM_DASHBOARD_PORT")
	if port == "" {
		port = "8088"
	}

	r := mux.NewRouter()
	
	// API routes for the React Dashboard
	api := r.PathPrefix("/quantum/api").Subrouter()
	api.HandleFunc("/readiness", getQuantumReadinessHandler).Methods("GET")
	api.HandleFunc("/crypto-inventory", getCryptoInventoryHandler).Methods("GET")
	api.HandleFunc("/metrics", getMetricsHandler).Methods("GET")
	
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# Quantum Dashboard Metrics\nquantum_dashboard_requests_total 0\n"))
	}).Methods("GET")

	log.Printf("Quantum Dashboard API starting on port %s", port)
	
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
