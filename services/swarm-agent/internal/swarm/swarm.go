// Package swarm implements a distributed swarm intelligence defense system
// with Byzantine fault-tolerant consensus. Autonomous agents collaborate
// to detect and respond to threats across the network perimeter.
package swarm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Agent model
// ──────────────────────────────────────────────

// AgentRole defines what type of defense an agent specializes in.
type AgentRole string

const (
	RoleScout    AgentRole = "scout"     // Network reconnaissance detection
	RoleSentinel AgentRole = "sentinel"  // Perimeter monitoring
	RoleHunter   AgentRole = "hunter"    // Active threat hunting
	RoleHealer   AgentRole = "healer"    // Incident containment
	RoleAnalyst  AgentRole = "analyst"   // Deep packet inspection
)

// Agent is a single autonomous defense agent in the swarm.
type Agent struct {
	ID          string    `json:"id"`
	Role        AgentRole `json:"role"`
	Zone        string    `json:"zone"`        // Network zone assignment
	Reputation  float64   `json:"reputation"`  // Trust score (0-1)
	Alive       bool      `json:"alive"`
	LastSeen    time.Time `json:"last_seen"`
	Detections  int64     `json:"detections"`
}

// ThreatSignal is a message agents share about observed threats.
type ThreatSignal struct {
	AgentID     string    `json:"agent_id"`
	ThreatType  string    `json:"threat_type"`
	Confidence  float64   `json:"confidence"`
	SourceIP    string    `json:"source_ip,omitempty"`
	TargetZone  string    `json:"target_zone"`
	Timestamp   time.Time `json:"timestamp"`
	Evidence    string    `json:"evidence,omitempty"`
}

// ConsensusDecision is the result of Byzantine consensus on a threat.
type ConsensusDecision struct {
	ThreatType  string    `json:"threat_type"`
	Approved    bool      `json:"approved"`
	VotesFor    int       `json:"votes_for"`
	VotesAgainst int      `json:"votes_against"`
	Confidence  float64   `json:"confidence"`
	Action      string    `json:"action"`
	DecidedAt   time.Time `json:"decided_at"`
}

// ──────────────────────────────────────────────
// Swarm Manager
// ──────────────────────────────────────────────

// SwarmManager coordinates the swarm of defense agents.
type SwarmManager struct {
	mu      sync.RWMutex
	agents  map[string]*Agent
	signals chan ThreatSignal
	stopCh  chan struct{}
	config  SwarmConfig
}

// SwarmConfig configures the swarm behavior.
type SwarmConfig struct {
	MinAgentsForConsensus int           `json:"min_agents"`
	ByzantineThreshold    float64       `json:"byzantine_threshold"` // f < n/3
	SignalBufferSize      int           `json:"signal_buffer_size"`
	HeartbeatInterval     time.Duration `json:"heartbeat_interval"`
	ReputationDecay       float64       `json:"reputation_decay"`
}

// DefaultSwarmConfig returns sensible defaults.
func DefaultSwarmConfig() SwarmConfig {
	return SwarmConfig{
		MinAgentsForConsensus: 5,
		ByzantineThreshold:    0.334, // Must have >2/3 agreement
		SignalBufferSize:      1000,
		HeartbeatInterval:     10 * time.Second,
		ReputationDecay:       0.995,
	}
}

// NewSwarmManager creates a new swarm coordinator.
func NewSwarmManager(cfg SwarmConfig) *SwarmManager {
	return &SwarmManager{
		agents:  make(map[string]*Agent),
		signals: make(chan ThreatSignal, cfg.SignalBufferSize),
		stopCh:  make(chan struct{}),
		config:  cfg,
	}
}

// SpawnAgent creates and registers a new agent.
func (sm *SwarmManager) SpawnAgent(role AgentRole, zone string) *Agent {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := fmt.Sprintf("agent-%s-%s-%04d", role, zone, rand.Intn(10000))
	agent := &Agent{
		ID:         id,
		Role:       role,
		Zone:       zone,
		Reputation: 1.0,
		Alive:      true,
		LastSeen:   time.Now(),
	}
	sm.agents[id] = agent
	log.Printf("[Swarm] Spawned agent %s (role=%s, zone=%s)", id, role, zone)
	return agent
}

// ReportThreat allows an agent to broadcast a threat signal.
func (sm *SwarmManager) ReportThreat(signal ThreatSignal) {
	select {
	case sm.signals <- signal:
	default:
		log.Printf("[Swarm] Signal buffer full — dropping signal from %s", signal.AgentID)
	}
}

// Start begins the swarm coordination loops.
func (sm *SwarmManager) Start(ctx context.Context) {
	log.Println("[Swarm] Manager started")
	go sm.signalProcessor(ctx)
	go sm.heartbeatMonitor(ctx)
}

// Stop shuts down the swarm.
func (sm *SwarmManager) Stop() {
	close(sm.stopCh)
}

// ── Signal processing & consensus ──────────────

func (sm *SwarmManager) signalProcessor(ctx context.Context) {
	// Batch signals for consensus
	batch := make([]ThreatSignal, 0, 10)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopCh:
			return
		case sig := <-sm.signals:
			batch = append(batch, sig)
		case <-ticker.C:
			if len(batch) > 0 {
				decision := sm.runConsensus(batch)
				if decision.Approved {
					sm.executeAction(decision)
				}
				batch = batch[:0]
			}
		}
	}
}

func (sm *SwarmManager) runConsensus(signals []ThreatSignal) ConsensusDecision {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Weight votes by agent reputation
	var weightedFor, weightedAgainst float64
	votesFor, votesAgainst := 0, 0

	// Group by threat type and vote
	threatType := signals[0].ThreatType
	for _, sig := range signals {
		agent, ok := sm.agents[sig.AgentID]
		if !ok || !agent.Alive {
			continue
		}
		if sig.Confidence >= 0.5 {
			weightedFor += agent.Reputation * sig.Confidence
			votesFor++
		} else {
			weightedAgainst += agent.Reputation * (1 - sig.Confidence)
			votesAgainst++
		}
	}

	totalWeight := weightedFor + weightedAgainst
	confidence := 0.0
	if totalWeight > 0 {
		confidence = weightedFor / totalWeight
	}

	approved := confidence > (1 - sm.config.ByzantineThreshold) // >2/3 threshold
	action := "monitor"
	if approved && confidence > 0.9 {
		action = "block_and_isolate"
	} else if approved {
		action = "alert_and_investigate"
	}

	decision := ConsensusDecision{
		ThreatType:   threatType,
		Approved:     approved,
		VotesFor:     votesFor,
		VotesAgainst: votesAgainst,
		Confidence:   confidence,
		Action:       action,
		DecidedAt:    time.Now(),
	}

	log.Printf("[Swarm] Consensus: %s approved=%v confidence=%.2f action=%s",
		threatType, approved, confidence, action)

	return decision
}

func (sm *SwarmManager) executeAction(d ConsensusDecision) {
	// In production: dispatch to SOAR playbook engine or firewall controller
	log.Printf("[Swarm] Executing action: %s for threat %s", d.Action, d.ThreatType)
}

func (sm *SwarmManager) heartbeatMonitor(ctx context.Context) {
	ticker := time.NewTicker(sm.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopCh:
			return
		case <-ticker.C:
			sm.mu.Lock()
			for _, agent := range sm.agents {
				if time.Since(agent.LastSeen) > 3*sm.config.HeartbeatInterval {
					agent.Alive = false
				}
				agent.Reputation *= sm.config.ReputationDecay
			}
			sm.mu.Unlock()
		}
	}
}

// GetAgents returns all registered agents.
func (sm *SwarmManager) GetAgents() []*Agent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	agents := make([]*Agent, 0, len(sm.agents))
	for _, a := range sm.agents {
		agents = append(agents, a)
	}
	return agents
}

// ToJSON serializes a consensus decision.
func (d *ConsensusDecision) ToJSON() string {
	b, _ := json.MarshalIndent(d, "", "  ")
	return string(b)
}
