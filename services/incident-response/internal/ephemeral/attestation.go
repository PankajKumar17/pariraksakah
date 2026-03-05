// Package ephemeral provides runtime attestation for ephemeral pods.
// Verifies that pods have not been tampered with using hash-based
// integrity checks and TPM-like attestation (simulated).
package ephemeral

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// AttestationResult captures the outcome of a pod integrity check.
type AttestationResult struct {
	PodName       string    `json:"pod_name"`
	Namespace     string    `json:"namespace"`
	Attested      bool      `json:"attested"`
	IntegrityHash string    `json:"integrity_hash"`
	Timestamp     time.Time `json:"timestamp"`
	Measurements  []Measurement `json:"measurements"`
	Verdict       string    `json:"verdict"` // pass, warn, fail
}

// Measurement is a single integrity measurement (hash of a component).
type Measurement struct {
	Component string `json:"component"` // filesystem, process_list, network_config
	Hash      string `json:"hash"`
	Expected  string `json:"expected,omitempty"`
	Match     bool   `json:"match"`
}

// Attestor verifies pod runtime integrity.
type Attestor struct {
	expectedHashes map[string]map[string]string // pod -> component -> expected hash
}

// NewAttestor creates a new attestation engine.
func NewAttestor() *Attestor {
	return &Attestor{
		expectedHashes: make(map[string]map[string]string),
	}
}

// RegisterBaseline stores the expected integrity hashes for a pod.
func (a *Attestor) RegisterBaseline(podName string, componentHashes map[string]string) {
	a.expectedHashes[podName] = componentHashes
	log.Printf("[Attestor] Baseline registered for pod %s (%d components)", podName, len(componentHashes))
}

// Attest performs runtime integrity verification of a pod.
func (a *Attestor) Attest(podName, namespace string, currentState map[string][]byte) AttestationResult {
	result := AttestationResult{
		PodName:   podName,
		Namespace: namespace,
		Timestamp: time.Now(),
		Attested:  true,
		Verdict:   "pass",
	}

	expected, hasBaseline := a.expectedHashes[podName]
	if !hasBaseline {
		result.Verdict = "warn"
		result.Attested = false
		return result
	}

	allMatch := true
	for component, data := range currentState {
		hash := computeHash(data)
		exp, ok := expected[component]
		m := Measurement{
			Component: component,
			Hash:      hash,
			Expected:  exp,
			Match:     ok && hash == exp,
		}
		result.Measurements = append(result.Measurements, m)
		if !m.Match {
			allMatch = false
		}
	}

	if !allMatch {
		result.Verdict = "fail"
		result.Attested = false
		log.Printf("[Attestor] INTEGRITY FAILURE for pod %s/%s", namespace, podName)
	}

	// Compute composite integrity hash
	compositeInput := ""
	for _, m := range result.Measurements {
		compositeInput += m.Hash
	}
	result.IntegrityHash = computeHash([]byte(compositeInput))

	return result
}

// computeHash returns the SHA-256 hex digest of data.
func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// GenerateBootMeasurement simulates a TPM-like boot measurement.
func GenerateBootMeasurement(podName string, imageDigest string, envVars map[string]string) Measurement {
	input := fmt.Sprintf("pod=%s;image=%s", podName, imageDigest)
	for k, v := range envVars {
		input += fmt.Sprintf(";%s=%s", k, v)
	}
	h := sha256.Sum256([]byte(input))
	return Measurement{
		Component: "boot_measurement",
		Hash:      hex.EncodeToString(h[:]),
		Match:     true,
	}
}
