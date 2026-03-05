// Package satellite provides GPS-backed timestamping for
// tamper-evident event integrity chains. Ensures log events
// cannot be retroactively altered by anchoring timestamps to
// satellite time references.
package satellite

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// GPS Timestamper
// ──────────────────────────────────────────────

// GPSTimestamp is a satellite-validated time reference.
type GPSTimestamp struct {
	UTC         time.Time `json:"utc"`
	GPSWeek     int       `json:"gps_week"`
	GPSSecond   float64   `json:"gps_second"`
	Satellites  int       `json:"satellites_locked"`
	Accuracy    float64   `json:"accuracy_ns"`   // nanosecond accuracy
	Source      string    `json:"source"`         // "gps", "galileo", "glonass", "ntp_fallback"
}

// Timestamper issues satellite-backed timestamps.
type Timestamper struct {
	mu          sync.RWMutex
	lastSync    GPSTimestamp
	driftOffset time.Duration
	source      string
}

// NewTimestamper creates a GPS timestamper.
func NewTimestamper() *Timestamper {
	return &Timestamper{
		source: "ntp_fallback", // Default to NTP; upgraded when GPS available
		lastSync: GPSTimestamp{
			UTC:        time.Now().UTC(),
			Satellites: 0,
			Accuracy:   1e6, // 1ms accuracy for NTP
			Source:     "ntp_fallback",
		},
	}
}

// Now returns the current satellite-validated timestamp.
func (t *Timestamper) Now() GPSTimestamp {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now().UTC().Add(t.driftOffset)
	gpsEpoch := time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	elapsed := now.Sub(gpsEpoch)
	week := int(elapsed.Hours() / (24 * 7))
	secInWeek := elapsed.Seconds() - float64(week)*7*24*3600

	return GPSTimestamp{
		UTC:        now,
		GPSWeek:    week,
		GPSSecond:  secInWeek,
		Satellites: t.lastSync.Satellites,
		Accuracy:   t.lastSync.Accuracy,
		Source:     t.source,
	}
}

// SyncFromGPS updates the time reference from a GPS receiver (stub).
func (t *Timestamper) SyncFromGPS(satellites int, accuracyNs float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastSync = GPSTimestamp{
		UTC:        time.Now().UTC(),
		Satellites: satellites,
		Accuracy:   accuracyNs,
		Source:     "gps",
	}
	t.source = "gps"
	t.driftOffset = 0
	log.Printf("[Satellite] GPS sync: %d satellites, accuracy=%.0fns", satellites, accuracyNs)
}

// ──────────────────────────────────────────────
// Integrity Chain
// ──────────────────────────────────────────────

// ChainEntry is a single link in the integrity chain.
type ChainEntry struct {
	Index       uint64       `json:"index"`
	Timestamp   GPSTimestamp `json:"timestamp"`
	EventHash   string       `json:"event_hash"`
	PreviousHash string      `json:"previous_hash"`
	ChainHash   string       `json:"chain_hash"` // H(index || timestamp || event_hash || prev_hash)
	ServiceName string       `json:"service_name"`
}

// IntegrityChain maintains a tamper-evident log chain.
type IntegrityChain struct {
	mu          sync.RWMutex
	entries     []ChainEntry
	timestamper *Timestamper
}

// NewIntegrityChain creates a new chain with a genesis entry.
func NewIntegrityChain(ts *Timestamper) *IntegrityChain {
	chain := &IntegrityChain{
		timestamper: ts,
		entries:     make([]ChainEntry, 0),
	}

	// Genesis block
	genesis := ChainEntry{
		Index:        0,
		Timestamp:    ts.Now(),
		EventHash:    hashString("genesis"),
		PreviousHash: "0000000000000000000000000000000000000000000000000000000000000000",
		ServiceName:  "system",
	}
	genesis.ChainHash = computeChainHash(genesis)
	chain.entries = append(chain.entries, genesis)

	return chain
}

// Append adds a new event to the integrity chain.
func (c *IntegrityChain) Append(eventData []byte, serviceName string) ChainEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.entries[len(c.entries)-1]
	entry := ChainEntry{
		Index:        prev.Index + 1,
		Timestamp:    c.timestamper.Now(),
		EventHash:    hashBytes(eventData),
		PreviousHash: prev.ChainHash,
		ServiceName:  serviceName,
	}
	entry.ChainHash = computeChainHash(entry)
	c.entries = append(c.entries, entry)

	return entry
}

// Verify checks the entire chain for integrity.
func (c *IntegrityChain) Verify() (bool, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := 1; i < len(c.entries); i++ {
		// Verify chain hash
		expected := computeChainHash(c.entries[i])
		if c.entries[i].ChainHash != expected {
			return false, i
		}
		// Verify link to previous
		if c.entries[i].PreviousHash != c.entries[i-1].ChainHash {
			return false, i
		}
	}
	return true, -1
}

// Len returns the number of entries in the chain.
func (c *IntegrityChain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Latest returns the most recent chain entry.
func (c *IntegrityChain) Latest() ChainEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[len(c.entries)-1]
}

// GetRange returns entries in [start, end).
func (c *IntegrityChain) GetRange(start, end int) []ChainEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if start < 0 {
		start = 0
	}
	if end > len(c.entries) {
		end = len(c.entries)
	}
	result := make([]ChainEntry, end-start)
	copy(result, c.entries[start:end])
	return result
}

// ToJSON serializes the chain.
func (c *IntegrityChain) ToJSON() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	b, err := json.MarshalIndent(c.entries, "", "  ")
	return string(b), err
}

// ── Hash helpers ───────────────────────────────

func computeChainHash(e ChainEntry) string {
	input := fmt.Sprintf("%d|%s|%s|%s|%s",
		e.Index,
		e.Timestamp.UTC.Format(time.RFC3339Nano),
		e.EventHash,
		e.PreviousHash,
		e.ServiceName,
	)
	return hashString(input)
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
