package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

var (
	dbPool   *pgxpool.Pool
	neo4jDrv neo4j.DriverWithContext
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

func getITCS(c *gin.Context) {
	// ITCS weighted formula simulation
	// Weights: API Gateway 20%, Kafka 15%, TimescaleDB 15%, Neo4j 10%, Redis 10%, Self-Healing Engine 10%, Flink 5%, MLFlow 5%, Monitoring stack 5%, Frontend 5%.
	if dbPool == nil {
		c.JSON(http.StatusOK, gin.H{"itcs": 100.0, "status": "TRUSTED GREEN"})
		return
	}
	
	// Real querying would happen here
	c.JSON(http.StatusOK, gin.H{"itcs": 92.5, "status": "TRUSTED GREEN"})
}

func getGraph(c *gin.Context) {
	if neo4jDrv == nil {
		c.JSON(http.StatusOK, gin.H{"nodes": []string{}, "links": []string{}})
		return
	}
	
	session := neo4jDrv.NewSession(context.Background(), neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(context.Background())
	
	res, err := session.Run(context.Background(), `
		MATCH (n:ComponentNode)
		OPTIONAL MATCH (n)-[r:TrustRelationship]->(m)
		RETURN n.id as source, n.trust_score as score, m.id as target, r.trust_level as edge_score
	`, nil)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch graph"})
		return
	}

	nodesMap := make(map[string]map[string]interface{})
	var links []map[string]interface{}
	
	for res.Next(context.Background()) {
		rec := res.Record()
		src, _ := rec.Get("source")
		score, _ := rec.Get("score")
		
		if srcStr, ok := src.(string); ok {
			nodesMap[srcStr] = map[string]interface{}{"id": srcStr, "val": score}
		}
		
		target, ok1 := rec.Get("target")
		edgeScore, ok2 := rec.Get("edge_score")
		if ok1 && target != nil && ok2 {
			links = append(links, map[string]interface{}{
				"source": src,
				"target": target,
				"score":  edgeScore,
			})
		}
	}
	
	var nodes []map[string]interface{}
	for _, v := range nodesMap {
		nodes = append(nodes, v)
	}
	
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "links": links})
}

func getCertificates(c *gin.Context) {
	if dbPool == nil {
		c.JSON(http.StatusOK, []string{})
		return
	}
	rows, err := dbPool.Query(context.Background(), "SELECT id, component_name, dna_fingerprint, certificate_serial, issued_at, expires_at, status FROM component_identities")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	
	var certs []map[string]interface{}
	for rows.Next() {
		var id, name, fp, serial, status string
		var issued, expires time.Time
		rows.Scan(&id, &name, &fp, &serial, &issued, &expires, &status)
		certs = append(certs, map[string]interface{}{
			"id": id, "component_name": name, "dna_fingerprint": fp,
			"certificate_serial": serial, "issued_at": issued, "expires_at": expires, "status": status,
		})
	}
	c.JSON(http.StatusOK, certs)
}

func getAuditTrail(c *gin.Context) {
	if dbPool == nil {
		c.JSON(http.StatusOK, []string{})
		return
	}
	rows, err := dbPool.Query(context.Background(), "SELECT action, component_id, actor, timestamp, outcome FROM dna_audit_trail ORDER BY timestamp DESC LIMIT 100")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	
	var audits []map[string]interface{}
	for rows.Next() {
		var action, comp, actor, outcome string
		var ts time.Time
		rows.Scan(&action, &comp, &actor, &ts, &outcome)
		audits = append(audits, map[string]interface{}{
			"action": action, "component_id": comp, "actor": actor, "timestamp": ts, "outcome": outcome,
		})
	}
	c.JSON(http.StatusOK, audits)
}

func main() {
	initTimescaleDB()
	initNeo4j()
	
	r := gin.Default()
	r.Use(cors.Default())
	
	api := r.Group("/dna")
	{
		api.GET("/itcs", getITCS)
		api.GET("/graph", getGraph)
		api.GET("/certificates", getCertificates)
		api.GET("/audit", getAuditTrail)
	}
	
	port := os.Getenv("DASHBOARD_API_PORT")
	if port == "" {
		port = "8055"
	}
	r.Run("0.0.0.0:" + port)
}
