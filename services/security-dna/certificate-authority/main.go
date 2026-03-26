package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	rootCAKey  dilithium.PrivateKey
	rootCAPub  dilithium.PublicKey
	dbPool     *pgxpool.Pool
	kafkaProd  *kafka.Producer
)

type ComponentCert struct {
	ComponentID        string    `json:"component_id"`
	SerialNumber       string    `json:"serial_number"`
	DNAFingerprint     string    `json:"dna_fingerprint"`
	PublicKey          string    `json:"public_key"`
	Signature          string    `json:"signature"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Status             string    `json:"status"`
	TrustScore         float64   `json:"trust_score"`
	RevocationReason   string    `json:"revocation_reason,omitempty"`
}

func initCA() {
	var err error
	mode := dilithium.Mode3
	rootCAPub, rootCAKey, err = mode.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Root CA keys: %v", err)
	}
	log.Println("Generated Post-Quantum Root CA (CRYSTALS-Dilithium Mode3)")
}

func initDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://cybershield:changeme_postgres@timescaledb:5432/cybershield"
	}
	var err error
	dbPool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Printf("DB connection failed: %v", err)
	}
}

func initKafka() {
	broker := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if broker == "" {
		broker = "kafka:9092"
	}
	prod, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": broker})
	if err != nil {
		log.Printf("Kafka producer initialization failed: %v", err)
		return
	}
	kafkaProd = prod
}

func publishEvent(topic string, payload interface{}) {
	if kafkaProd == nil {
		return
	}
	val, err := json.Marshal(payload)
	if err == nil {
		_ = kafkaProd.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
			Value:          val,
		}, nil)
	}
}

func issueHandler(c *gin.Context) {
	compID := c.Param("component_id")
	dnaFP := c.Query("dna_fingerprint")
	mode := dilithium.Mode3
	pub, _, _ := mode.GenerateKey(rand.Reader) // Simulate client keypair for demo
	pubBytes := pub.Bytes()
	
	serial := fmt.Sprintf("serial-%s-%d", compID, time.Now().Unix())
	now := time.Now()
	exp := now.Add(24 * time.Hour * 365)
	
	certBody := fmt.Sprintf("%s:%s:%s", compID, dnaFP, hex.EncodeToString(pubBytes))
	signature := mode.Sign(rootCAKey, []byte(certBody))
	
	cert := ComponentCert{
		ComponentID:    compID,
		SerialNumber:   serial,
		DNAFingerprint: dnaFP,
		PublicKey:      hex.EncodeToString(pubBytes),
		Signature:      hex.EncodeToString(signature),
		IssuedAt:       now,
		ExpiresAt:      exp,
		Status:         "ACTIVE",
		TrustScore:     100.0,
	}
	
	if dbPool != nil {
		_, _ = dbPool.Exec(context.Background(), `
			INSERT INTO component_identities 
			(id, component_name, component_type, dna_fingerprint, public_key, certificate_serial, issued_at, expires_at, trust_score, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET certificate_serial=$6, public_key=$5, dna_fingerprint=$4`,
			cert.ComponentID, cert.ComponentID, "service", cert.DNAFingerprint, cert.PublicKey, cert.SerialNumber, cert.IssuedAt, cert.ExpiresAt, cert.TrustScore, cert.Status)
	}
	
	publishEvent("dna.identity.issued", cert)
	c.JSON(http.StatusOK, cert)
}

func revokeHandler(c *gin.Context) {
	compID := c.Param("component_id")
	if dbPool != nil {
		_, _ = dbPool.Exec(context.Background(), "UPDATE component_identities SET status='REVOKED' WHERE id=$1", compID)
	}
	payload := map[string]interface{}{
		"component_id": compID,
		"revoked_at":   time.Now().Format(time.RFC3339),
		"reason":       c.Query("reason"),
		"delta_score":  100.0,
	}
	publishEvent("dna.identity.revoked", payload)
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "component": compID})
}

func ocspHandler(c *gin.Context) {
	serial := c.Param("serial")
	var status string
	if dbPool != nil {
		err := dbPool.QueryRow(context.Background(), "SELECT status FROM component_identities WHERE certificate_serial=$1", serial).Scan(&status)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
	} else {
		status = "UNKNOWN"
	}
	c.JSON(http.StatusOK, gin.H{"serial": serial, "status": status})
}

func main() {
	initCA()
	initDB()
	initKafka()
	
	r := gin.Default()
	r.POST("/ca/issue/:component_id", issueHandler)
	r.POST("/ca/renew/:component_id", issueHandler) // Using issue for renewal simulation
	r.POST("/ca/revoke/:component_id", revokeHandler)
	r.GET("/ca/ocsp/:serial", ocspHandler)
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "dna_ca_certs_issued_total 1\n")
	})
	
	port := os.Getenv("CA_PORT")
	if port == "" {
		port = "8051"
	}
	r.Run("0.0.0.0:" + port)
}
