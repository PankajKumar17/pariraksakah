// Package ephemeral implements a Kubernetes custom controller for
// ephemeral infrastructure — automatically rotating pods, nodes, and
// network segments on configurable intervals to deny persistent footholds.
package ephemeral

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────

// RotationConfig defines how often each infrastructure layer rotates.
type RotationConfig struct {
	PodRotationInterval     time.Duration `json:"pod_rotation_interval"`     // e.g., 4h
	NetworkRotationInterval time.Duration `json:"network_rotation_interval"` // e.g., 1h
	SecretRotationInterval  time.Duration `json:"secret_rotation_interval"`  // e.g., 30m
	MaxPodAge               time.Duration `json:"max_pod_age"`               // force-kill threshold
	CanaryPercentage        float64       `json:"canary_percentage"`         // % traffic to canary
}

// DefaultConfig returns a sensible default rotation schedule.
func DefaultConfig() RotationConfig {
	return RotationConfig{
		PodRotationInterval:     4 * time.Hour,
		NetworkRotationInterval: 1 * time.Hour,
		SecretRotationInterval:  30 * time.Minute,
		MaxPodAge:               6 * time.Hour,
		CanaryPercentage:        10.0,
	}
}

// ──────────────────────────────────────────────
// Pod state model
// ──────────────────────────────────────────────

// EphemeralPod represents a managed pod in the rotation pool.
type EphemeralPod struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	CreatedAt   time.Time `json:"created_at"`
	Generation  int       `json:"generation"`
	Attested    bool      `json:"attested"`
	IntegrityOK bool      `json:"integrity_ok"`
}

// Age returns how long the pod has been running.
func (p *EphemeralPod) Age() time.Duration {
	return time.Since(p.CreatedAt)
}

// ──────────────────────────────────────────────
// Controller
// ──────────────────────────────────────────────

// Controller manages ephemeral infrastructure rotation.
type Controller struct {
	mu     sync.RWMutex
	config RotationConfig
	pods   map[string]*EphemeralPod
	stopCh chan struct{}
	stats  RotationStats
}

// RotationStats tracks operational metrics.
type RotationStats struct {
	TotalRotations      int64     `json:"total_rotations"`
	FailedRotations     int64     `json:"failed_rotations"`
	LastRotationAt      time.Time `json:"last_rotation_at"`
	ActivePods          int       `json:"active_pods"`
	AverageUptimeSec    float64   `json:"average_uptime_sec"`
}

// NewController creates a new ephemeral infrastructure controller.
func NewController(cfg RotationConfig) *Controller {
	return &Controller{
		config: cfg,
		pods:   make(map[string]*EphemeralPod),
		stopCh: make(chan struct{}),
	}
}

// Start begins the rotation control loops.
func (c *Controller) Start(ctx context.Context) {
	log.Println("[Ephemeral] Controller started")

	go c.podRotationLoop(ctx)
	go c.networkRotationLoop(ctx)
	go c.secretRotationLoop(ctx)
	go c.integrityCheckLoop(ctx)
}

// Stop gracefully shuts down the controller.
func (c *Controller) Stop() {
	close(c.stopCh)
	log.Println("[Ephemeral] Controller stopped")
}

// GetStats returns current rotation statistics.
func (c *Controller) GetStats() RotationStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.stats.ActivePods = len(c.pods)
	return c.stats
}

// ── Rotation Loops ─────────────────────────────

func (c *Controller) podRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.PodRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.rotatePods(ctx)
		}
	}
}

func (c *Controller) networkRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.NetworkRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.rotateNetworkSegments(ctx)
		}
	}
}

func (c *Controller) secretRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.SecretRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.rotateSecrets(ctx)
		}
	}
}

func (c *Controller) integrityCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkIntegrity(ctx)
		}
	}
}

// ── Rotation logic ─────────────────────────────

func (c *Controller) rotatePods(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rotated := 0
	for name, pod := range c.pods {
		if pod.Age() > c.config.MaxPodAge {
			log.Printf("[Ephemeral] Rotating pod %s (age: %s)", name, pod.Age())
			// In production: call K8s API to delete pod and let ReplicaSet recreate
			newPod := &EphemeralPod{
				Name:       name,
				Namespace:  pod.Namespace,
				CreatedAt:  time.Now(),
				Generation: pod.Generation + 1,
			}
			c.pods[name] = newPod
			rotated++
		}
	}

	if rotated > 0 {
		c.stats.TotalRotations += int64(rotated)
		c.stats.LastRotationAt = time.Now()
		log.Printf("[Ephemeral] Rotated %d pods", rotated)
	}
}

func (c *Controller) rotateNetworkSegments(_ context.Context) {
	// In production: update Cilium/Calico network policies to rotate
	// micro-segment assignments, IP ranges, and egress rules
	log.Printf("[Ephemeral] Network segment rotation triggered")
	c.mu.Lock()
	c.stats.TotalRotations++
	c.stats.LastRotationAt = time.Now()
	c.mu.Unlock()
}

func (c *Controller) rotateSecrets(_ context.Context) {
	// In production: generate new TLS certs, API keys, DB passwords via Vault
	log.Printf("[Ephemeral] Secret rotation triggered")
	c.mu.Lock()
	c.stats.TotalRotations++
	c.stats.LastRotationAt = time.Now()
	c.mu.Unlock()
}

func (c *Controller) checkIntegrity(_ context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for name, pod := range c.pods {
		if !pod.IntegrityOK {
			log.Printf("[Ephemeral] Integrity check FAILED for pod %s — force rotating", name)
			c.pods[name] = &EphemeralPod{
				Name:       name,
				Namespace:  pod.Namespace,
				CreatedAt:  time.Now(),
				Generation: pod.Generation + 1,
			}
			c.stats.FailedRotations++
		}
	}
}

// RegisterPod adds a pod to the managed rotation pool.
func (c *Controller) RegisterPod(name, namespace string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pods[name] = &EphemeralPod{
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now(),
		Attested:  true,
		IntegrityOK: true,
	}
	log.Printf("[Ephemeral] Registered pod %s/%s", namespace, name)
}

// GenerateEphemeralID creates a random short-lived identifier.
func GenerateEphemeralID() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return fmt.Sprintf("eph-%s", string(b))
}
