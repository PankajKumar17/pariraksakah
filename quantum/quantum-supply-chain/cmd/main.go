package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// In an actual implementation, signature verification would call out to the quantum-safe-crypto Rust engine
// using SPHINCS+ or FALCON via HTTP or gRPC.

type MerkleNode struct {
	Hash      string        `json:"hash"`
	Left      *MerkleNode   `json:"left,omitempty"`
	Right     *MerkleNode   `json:"right,omitempty"`
	Artifact  *ArtifactMeta `json:"artifact,omitempty"`
	Signature string        `json:"quantum_signature,omitempty"`
}

type ArtifactMeta struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

var (
	artifacts = make(map[string]ArtifactMeta)
	treeCache *MerkleNode
	mutex     sync.RWMutex
)

// Quantum-safe signature dummy wrapper
func quantumSign(data string, algo string) string {
	hash := sha256.Sum256([]byte(data + time.Now().String()))
	return fmt.Sprintf("%s-sig-%x", algo, hash)
}

func buildMerkleTree(nodes []MerkleNode) *MerkleNode {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return &nodes[0]
	}

	var newLevel []MerkleNode
	for i := 0; i < len(nodes); i += 2 {
		if i+1 < len(nodes) {
			combined := nodes[i].Hash + nodes[i+1].Hash
			hash := sha256.Sum256([]byte(combined))
			parent := MerkleNode{
				Hash:      fmt.Sprintf("%x", hash),
				Left:      &nodes[i],
				Right:     &nodes[i+1],
				Signature: quantumSign(fmt.Sprintf("%x", hash), "SPHINCS+-SHA2-128F"),
			}
			newLevel = append(newLevel, parent)
		} else {
			newLevel = append(newLevel, nodes[i])
		}
	}
	return buildMerkleTree(newLevel)
}

func updateTree() {
	mutex.Lock()
	defer mutex.Unlock()
	var nodes []MerkleNode
	for id, art := range artifacts {
		hash := sha256.Sum256([]byte(id + art.Type))
		copyArt := art
		nodes = append(nodes, MerkleNode{
			Hash:      fmt.Sprintf("%x", hash),
			Artifact:  &copyArt,
			Signature: quantumSign(fmt.Sprintf("%x", hash), "FALCON-512"),
		})
	}
	treeCache = buildMerkleTree(nodes)
}

// ── Handlers ──

func verifyArtifactHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID   string `json:"artifact_id"`
		ArtifactType string `json:"artifact_type"`
		ArtifactHash string `json:"artifact_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// In real setup, verify req.ArtifactHash matches DB & signature via Rust PQC engine
	// Simulate verification
	algo := "SPHINCS+-SHA2-128F"
	if req.ArtifactType == "source_code" {
		algo = "FALCON-512"
	} else if req.ArtifactType == "dependency" {
		algo = "CRYSTALS-Dilithium-5"
	}

	// Simulate Trivy Integration via trust score check
	trivyVulnerabilities := 0
	if req.ArtifactType == "dependency" {
		trivyVulnerabilities = 2 // Simulated finding
	}

	result := map[string]interface{}{
		"artifact_id":         req.ArtifactID,
		"verification_result": "verified",
		"tamper_detected":     false,
		"quantum_signature":   quantumSign(req.ArtifactHash, algo),
		"algorithm_used":      algo,
		"trivy_vulnerabilities": trivyVulnerabilities,
	}

	log.Printf("Verified artifact %s with %s", req.ArtifactID, algo)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func signArtifactHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID   string `json:"artifact_id"`
		ArtifactType string `json:"artifact_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mutex.Lock()
	artifacts[req.ArtifactID] = ArtifactMeta{ID: req.ArtifactID, Type: req.ArtifactType}
	mutex.Unlock()
	
	updateTree()

	algo := "SPHINCS+-SHA2-128F"
	hash := sha256.Sum256([]byte(req.ArtifactID + req.ArtifactType))
	sig := quantumSign(fmt.Sprintf("%x", hash), algo)

	result := map[string]interface{}{
		"artifact_id":       req.ArtifactID,
		"quantum_signature": sig,
		"algorithm":         algo,
		"status":            "signed_and_added_to_merkle_tree",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func getMerkleTreeHandler(w http.ResponseWriter, r *http.Request) {
	mutex.RLock()
	defer mutex.RUnlock()

	if treeCache == nil {
		http.Error(w, `{"error": "Tree empty"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"root_hash":         treeCache.Hash,
		"quantum_signature": treeCache.Signature,
		"artifact_count":    len(artifacts),
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy","service":"quantum-supply-chain"}`))
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("# Quantum Supply Chain Metrics\nquantum_supply_chain_verifications_total 0\n"))
}

func main() {
	// Add some dummy initial data
	artifacts["ubuntu:latest"] = ArtifactMeta{ID: "ubuntu:latest", Type: "container_image"}
	artifacts["react:18.2"] = ArtifactMeta{ID: "react:18.2", Type: "dependency"}
	updateTree()

	port := os.Getenv("QUANTUM_SUPPLY_PORT")
	if port == "" {
		port = "8085"
	}

	r := mux.NewRouter()
	r.HandleFunc("/quantum/supplychain/verify", verifyArtifactHandler).Methods("POST")
	r.HandleFunc("/quantum/supplychain/sign", signArtifactHandler).Methods("POST")
	r.HandleFunc("/quantum/supplychain/merkle", getMerkleTreeHandler).Methods("GET")
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/metrics", metricsHandler).Methods("GET")

	log.Printf("Quantum Supply Chain Verification Service starting on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
