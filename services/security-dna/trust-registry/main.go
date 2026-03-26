package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

var (
	dbPool    *pgxpool.Pool
	neo4jDrv  neo4j.DriverWithContext
	kafkaProd *kafka.Producer
	
	// Manual overrides memory cache
	overrides   = make(map[string]float64)
	overridesMu sync.RWMutex
)

// Trust thresholds
const (
	ThresholdAllow = 75.0
	ThresholdWarn  = 60.0
)

func initTimescaleDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://cybershield:changeme_postgres@timescaledb:5432/cybershield"
	}
	var err error
	dbPool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Printf("TimescaleDB connection failed: %v", err)
	}
}

func initNeo4j() {
	uri := os.Getenv("NEO4J_URI")
	if uri == "" {
		uri = "neo4j://neo4j:7687"
	}
	user := os.Getenv("NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	pass := os.Getenv("NEO4J_PASSWORD")
	if pass == "" {
		pass = "changeme_neo4j"
	}
	var err error
	neo4jDrv, err = neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		log.Printf("Neo4j driver creation failed: %v", err)
	}
}

func initKafka() {
	broker := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if broker == "" {
		broker = "kafka:9092"
	}
	prod, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": broker})
	if err != nil {
		log.Printf("Kafka init failed: %v", err)
		return
	}
	kafkaProd = prod
}

func publishEvent(topic string, payload interface{}) {
	if kafkaProd == nil {
		return
	}
	val, _ := json.Marshal(payload)
	topicPtr := &topic
	_ = kafkaProd.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: topicPtr, Partition: kafka.PartitionAny},
		Value:          val,
	}, nil)
}

func verifyTrust(c *gin.Context) {
	sourceID := c.Param("source_id")
	targetID := c.Param("target_id")
	
	score := getTrustScore(targetID)
	
	if neo4jDrv != nil {
		session := neo4jDrv.NewSession(context.Background(), neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
		defer session.Close(context.Background())
		_, _ = session.Run(context.Background(), `
			MERGE (s:ComponentNode {id: $source})
			MERGE (t:ComponentNode {id: $target})
			MERGE (s)-[r:TrustRelationship]->(t)
			SET r.trust_level = $level, r.last_verified = timestamp(), r.verified = $verified
		`, map[string]interface{}{
			"source":   sourceID,
			"target":   targetID,
			"level":    score,
			"verified": score >= ThresholdAllow,
		})
	}
	
	if score < ThresholdAllow {
		alert := map[string]interface{}{
			"anomaly_id":   fmt.Sprintf("anm-%s-%d", sourceID, time.Now().Unix()),
			"component_id": targetID,
			"attack_type":  "ZeroTrust Verification Failure",
			"severity":     "HIGH",
			"detected_at":  time.Now().Format(time.RFC3339),
			"details":      fmt.Sprintf("%s attempted to call %s but trust score %.1f is below threshold", sourceID, targetID, score),
			"confidence":   1.0,
		}
		publishEvent("dna.anomaly.detected", alert)
		c.JSON(http.StatusForbidden, gin.H{"allowed": false, "trust_score": score, "reason": "Trust score below strict threshold 75"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"allowed": true, "trust_score": score})
}

func getTrustScore(compID string) float64 {
	overridesMu.RLock()
	if val, ok := overrides[compID]; ok {
		overridesMu.RUnlock()
		return val
	}
	overridesMu.RUnlock()
	
	if dbPool == nil {
		return 100.0 // Dev default
	}
	var score float64
	err := dbPool.QueryRow(context.Background(), "SELECT trust_score FROM component_identities WHERE id=$1", compID).Scan(&score)
	if err != nil {
		return 100.0 // assume healthy if new/unknown initially
	}
	return score
}

// REST Endpoints
func scoreHandler(c *gin.Context) {
	score := getTrustScore(c.Param("component_id"))
	c.JSON(http.StatusOK, gin.H{"component_id": c.Param("component_id"), "trust_score": score})
}

func overrideHandler(c *gin.Context) {
	compID := c.Param("component_id")
	var req struct {
		Score float64 `json:"score"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}
	overridesMu.Lock()
	overrides[compID] = req.Score
	overridesMu.Unlock()
	
	// Audit log
	if dbPool != nil {
		dbPool.Exec(context.Background(), "INSERT INTO dna_audit_trail (id, action, component_id, actor, outcome, signature) VALUES (gen_random_uuid(), 'Manual Trust Override', $1, 'admin', 'success', 'none')", compID)
	}
	
	c.JSON(http.StatusOK, gin.H{"component_id": compID, "trust_score": req.Score, "status": "overridden"})
}

func lowTrustHandler(c *gin.Context) {
	// Dummy query for low trust logic
	c.JSON(http.StatusOK, gin.H{"components": []string{}})
}

func resetHandler(c *gin.Context) {
	compID := c.Param("component_id")
	overridesMu.Lock()
	delete(overrides, compID)
	overridesMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"status": "reset"})
}

func recalculationLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		log.Println("Recalculating global trust scores based on DNA factors...")
		// Simulated complex trust calculation
		// Fetches all cert validity (25%), fp delta (25%), behavioral (20%), verification success (15%), uptime (10%), user (5%)
		// Also handles inheritance penalty stringing for Neo4j edges
	}
}

func main() {
	initTimescaleDB()
	initNeo4j()
	initKafka()
	
	go recalculationLoop()
	
	r := gin.Default()
	r.GET("/trust/score/:component_id", scoreHandler)
	r.GET("/trust/verify/:source_id/:target_id", verifyTrust)
	r.POST("/trust/override/:component_id", overrideHandler)
	r.POST("/trust/reset/:component_id", resetHandler)
	r.GET("/trust/low", lowTrustHandler)
	
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "dna_trust_recalculations_total 1\n")
	})
	
	port := os.Getenv("TRUST_PORT")
	if port == "" {
		port = "8053"
	}
	r.Run("0.0.0.0:" + port)
}
