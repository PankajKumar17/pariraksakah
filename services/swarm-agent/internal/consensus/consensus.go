// Package consensus implements a Byzantine Fault Tolerant (BFT) consensus
// protocol for the CyberShield-X swarm defense network.
// Tolerates up to f < n/3 malicious or compromised agents.
package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// Phase represents the current consensus round phase.
type Phase int

const (
	PhasePrepare Phase = iota
	PhaseCommit
	PhaseDecide
)

// Message types in the BFT protocol.
type MessageType string

const (
	MsgPropose   MessageType = "PROPOSE"
	MsgPrepare   MessageType = "PREPARE"
	MsgCommit    MessageType = "COMMIT"
	MsgDecide    MessageType = "DECIDE"
)

// Proposal is a threat assessment submitted for consensus.
type Proposal struct {
	ID          string  `json:"id"`
	ThreatType  string  `json:"threat_type"`
	SourceAgent string  `json:"source_agent"`
	Evidence    string  `json:"evidence"`
	Confidence  float64 `json:"confidence"`
	Hash        string  `json:"hash"`
}

// Vote is a single agent's vote on a proposal.
type Vote struct {
	ProposalID string      `json:"proposal_id"`
	AgentID    string      `json:"agent_id"`
	Phase      Phase       `json:"phase"`
	Approve    bool        `json:"approve"`
	Timestamp  time.Time   `json:"timestamp"`
	Signature  string      `json:"signature"` // Agent-signed vote
}

// Round tracks the state of a single consensus round.
type Round struct {
	Proposal    *Proposal
	Phase       Phase
	PrepareVotes map[string]bool // agentID -> approve
	CommitVotes  map[string]bool
	Decided     bool
	Result      bool
	StartedAt   time.Time
}

// BFTConsensus implements simplified PBFT for the swarm.
type BFTConsensus struct {
	mu          sync.RWMutex
	nodeID      string
	totalNodes  int
	faultLimit  int              // max Byzantine faults tolerated: (n-1)/3
	rounds      map[string]*Round
	decideCh    chan *Round
}

// NewBFTConsensus creates a new BFT consensus engine.
func NewBFTConsensus(nodeID string, totalNodes int) *BFTConsensus {
	f := (totalNodes - 1) / 3
	return &BFTConsensus{
		nodeID:     nodeID,
		totalNodes: totalNodes,
		faultLimit: f,
		rounds:     make(map[string]*Round),
		decideCh:   make(chan *Round, 100),
	}
}

// Propose initiates a new consensus round for a threat assessment.
func (c *BFTConsensus) Propose(threatType, evidence string, confidence float64) *Proposal {
	id := generateProposalID(threatType, evidence)
	prop := &Proposal{
		ID:          id,
		ThreatType:  threatType,
		SourceAgent: c.nodeID,
		Evidence:    evidence,
		Confidence:  confidence,
		Hash:        hashData(threatType + evidence),
	}

	c.mu.Lock()
	c.rounds[id] = &Round{
		Proposal:     prop,
		Phase:        PhasePrepare,
		PrepareVotes: make(map[string]bool),
		CommitVotes:  make(map[string]bool),
		StartedAt:    time.Now(),
	}
	c.mu.Unlock()

	log.Printf("[BFT] Proposal %s initiated by %s: %s (confidence=%.2f)",
		id[:8], c.nodeID, threatType, confidence)
	return prop
}

// ReceivePrepare processes an incoming PREPARE vote.
func (c *BFTConsensus) ReceivePrepare(v Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	round, ok := c.rounds[v.ProposalID]
	if !ok || round.Phase != PhasePrepare {
		return
	}

	round.PrepareVotes[v.AgentID] = v.Approve

	// Check if we have 2f+1 matching PREPARE votes
	approvals := countApprovals(round.PrepareVotes)
	quorum := 2*c.faultLimit + 1

	if approvals >= quorum {
		round.Phase = PhaseCommit
		log.Printf("[BFT] Proposal %s → COMMIT phase (%d/%d prepare votes)",
			v.ProposalID[:8], approvals, quorum)
	}
}

// ReceiveCommit processes an incoming COMMIT vote.
func (c *BFTConsensus) ReceiveCommit(v Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	round, ok := c.rounds[v.ProposalID]
	if !ok || round.Phase != PhaseCommit {
		return
	}

	round.CommitVotes[v.AgentID] = v.Approve

	approvals := countApprovals(round.CommitVotes)
	quorum := 2*c.faultLimit + 1

	if approvals >= quorum && !round.Decided {
		round.Decided = true
		round.Result = true
		round.Phase = PhaseDecide
		log.Printf("[BFT] Proposal %s DECIDED: APPROVED (%d/%d commit votes)",
			v.ProposalID[:8], approvals, quorum)

		// Non-blocking send to decide channel
		select {
		case c.decideCh <- round:
		default:
		}
	}
}

// DecideChan returns the channel that emits decided rounds.
func (c *BFTConsensus) DecideChan() <-chan *Round {
	return c.decideCh
}

// GetRoundStatus returns the current state of a consensus round.
func (c *BFTConsensus) GetRoundStatus(proposalID string) (*Round, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.rounds[proposalID]
	return r, ok
}

// FaultTolerance returns the max Byzantine faults this configuration can handle.
func (c *BFTConsensus) FaultTolerance() int {
	return c.faultLimit
}

// ── Helpers ────────────────────────────────────

func countApprovals(votes map[string]bool) int {
	count := 0
	for _, approved := range votes {
		if approved {
			count++
		}
	}
	return count
}

func generateProposalID(threatType, evidence string) string {
	data := fmt.Sprintf("%s:%s:%d", threatType, evidence, time.Now().UnixNano())
	return hashData(data)
}

func hashData(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
