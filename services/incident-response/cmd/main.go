// CyberShield-X Incident Response Service — SOAR Engine
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ── Data models ────────────────────────────────

type Incident struct {
	ID          string            `json:"id"`
	AlertType   string            `json:"alert_type"`
	Severity    string            `json:"severity"`
	SourceIP    string            `json:"source_ip"`
	Host        string            `json:"host"`
	Description string            `json:"description"`
	Status      string            `json:"status"` // open,investigating,contained,resolved
	PlaybookRun *PlaybookExecution `json:"playbook_run,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type PlaybookExecution struct {
	PlaybookName string         `json:"playbook_name"`
	Status       string         `json:"status"` // running,completed,failed
	Steps        []StepResult   `json:"steps"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
}

type StepResult struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Status  string `json:"status"` // success,failed,skipped
	Output  string `json:"output"`
	Elapsed int64  `json:"elapsed_ms"`
}

type PlaybookDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Triggers    []string `json:"triggers"`
	StepCount   int      `json:"step_count"`
	FilePath    string   `json:"file_path"`
}

type CreateIncidentRequest struct {
	AlertType   string `json:"alert_type"`
	Severity    string `json:"severity"`
	SourceIP    string `json:"source_ip"`
	Host        string `json:"host"`
	Description string `json:"description"`
}

// ── In-memory store ────────────────────────────

var (
	incidents   = make(map[string]*Incident)
	incidentsMu sync.RWMutex
	stats       = map[string]int{
		"total_incidents": 0,
		"auto_contained": 0,
		"resolved":        0,
		"mean_ttr_seconds": 0,
	}
)

// ── Playbook store ─────────────────────────────

var builtinPlaybooks = map[string][]map[string]string{
	"ransomware_response": {
		{"name": "notify_soc_initial",      "action": "notify",           "detail": "Alert SOC on #soc-critical channel"},
		{"name": "isolate_affected_host",   "action": "isolate_host",     "detail": "Block all inbound/outbound on affected host"},
		{"name": "block_c2_ip",             "action": "block_ip",         "detail": "Add source IP to firewall deny-list"},
		{"name": "snapshot_forensic",       "action": "snapshot_forensic","detail": "Capture memory + disk forensic snapshot"},
		{"name": "enrich_ioc",              "action": "enrich_ioc",       "detail": "Query VirusTotal / OTX for IOC enrichment"},
		{"name": "restore_from_backup",     "action": "restore_backup",   "detail": "Restore clean baseline from last known-good snapshot"},
		{"name": "notify_soc_complete",     "action": "notify",           "detail": "Notify SOC: containment complete, monitoring active"},
	},
	"lateral_movement_response": {
		{"name": "notify_soc",             "action": "notify",        "detail": "Alert SOC — lateral movement detected"},
		{"name": "isolate_source_host",    "action": "isolate_host",  "detail": "Isolate the originating host from the network"},
		{"name": "revoke_credentials",     "action": "revoke_creds",  "detail": "Revoke compromised user credentials"},
		{"name": "scan_destination_host",  "action": "vulnerability_scan","detail": "Scan destination host for persistence mechanisms"},
		{"name": "patch_exploit_vector",   "action": "patch",         "detail": "Push emergency patch to close exploit vector"},
	},
	"phishing_response": {
		{"name": "quarantine_email",       "action": "quarantine_email","detail": "Pull phishing email from all mailboxes"},
		{"name": "block_sender_domain",    "action": "block_domain",   "detail": "Add sender domain to email blocklist"},
		{"name": "scan_clicked_users",     "action": "endpoint_scan",  "detail": "Run EDR scan on users who opened the email"},
		{"name": "reset_credentials",     "action": "reset_password", "detail": "Force credential reset for exposed users"},
		{"name": "notify_users",          "action": "notify",         "detail": "Send awareness notification to all users"},
	},
	"generic_response": {
		{"name": "notify_soc",     "action": "notify",     "detail": "Alert SOC team"},
		{"name": "enrich_ioc",     "action": "enrich_ioc", "detail": "Enrich indicators via OSINT feeds"},
		{"name": "block_source",   "action": "block_ip",   "detail": "Block source IP in firewall"},
		{"name": "collect_logs",   "action": "collect_logs","detail": "Collect and preserve relevant log evidence"},
	},
}

func selectPlaybook(alertType string) string {
	switch {
	case strings.Contains(alertType, "ransomware"):
		return "ransomware_response"
	case strings.Contains(alertType, "lateral"):
		return "lateral_movement_response"
	case strings.Contains(alertType, "phishing"):
		return "phishing_response"
	default:
		return "generic_response"
	}
}

// ── Playbook execution engine ──────────────────

func executePlaybook(incident *Incident, playbookName string) {
	steps := builtinPlaybooks[playbookName]
	exec := &PlaybookExecution{
		PlaybookName: playbookName,
		Status:       "running",
		Steps:        make([]StepResult, 0, len(steps)),
		StartedAt:    time.Now(),
	}

	incidentsMu.Lock()
	incident.Status = "investigating"
	incident.PlaybookRun = exec
	incidentsMu.Unlock()

	for _, step := range steps {
		t0 := time.Now()
		// Simulate the action execution (real integration would call actual APIs)
		time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond)
		elapsed := time.Since(t0).Milliseconds()

		result := StepResult{
			Name:    step["name"],
			Action:  step["action"],
			Status:  "success",
			Output:  fmt.Sprintf("✓ %s — executed against %s", step["detail"], incident.Host),
			Elapsed: elapsed,
		}
		// Occasional controlled failure (for realism)
		if rand.Float32() < 0.05 {
			result.Status = "failed"
			result.Output = fmt.Sprintf("⚠ %s — target unreachable, continuing", step["detail"])
		}

		incidentsMu.Lock()
		exec.Steps = append(exec.Steps, result)
		incidentsMu.Unlock()
	}

	now := time.Now()
	incidentsMu.Lock()
	exec.Status = "completed"
	exec.CompletedAt = &now
	incident.Status = "contained"
	incident.UpdatedAt = now
	stats["auto_contained"]++
	incidentsMu.Unlock()

	log.Printf("[SOAR] Incident %s contained via playbook %s in %dms",
		incident.ID, playbookName, time.Since(exec.StartedAt).Milliseconds())
}

// ── HTTP handlers ──────────────────────────────

func createIncident(w http.ResponseWriter, r *http.Request) {
	var req CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	if req.Host == "" {
		req.Host = req.SourceIP
	}

	inc := &Incident{
		ID:          fmt.Sprintf("INC-%d", time.Now().UnixMilli()),
		AlertType:   req.AlertType,
		Severity:    req.Severity,
		SourceIP:    req.SourceIP,
		Host:        req.Host,
		Description: req.Description,
		Status:      "open",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	incidentsMu.Lock()
	incidents[inc.ID] = inc
	stats["total_incidents"]++
	incidentsMu.Unlock()

	// Auto-execute playbook for critical/high incidents
	if req.Severity == "critical" || req.Severity == "high" {
		playbook := selectPlaybook(req.AlertType)
		go executePlaybook(inc, playbook)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(inc)
}

func listIncidents(w http.ResponseWriter, r *http.Request) {
	incidentsMu.RLock()
	defer incidentsMu.RUnlock()

	list := make([]*Incident, 0, len(incidents))
	for _, inc := range incidents {
		list = append(list, inc)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"incidents": list, "total": len(list), "stats": stats})
}

func getIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	incidentsMu.RLock()
	inc, ok := incidents[id]
	incidentsMu.RUnlock()
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

func executeIncidentPlaybook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	incidentsMu.RLock()
	inc, ok := incidents[id]
	incidentsMu.RUnlock()
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	playbook := selectPlaybook(inc.AlertType)
	go executePlaybook(inc, playbook)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Playbook execution started",
		"playbook": playbook,
		"incident": id,
	})
}

func listPlaybooks(w http.ResponseWriter, r *http.Request) {
	result := make([]map[string]interface{}, 0)
	for name, steps := range builtinPlaybooks {
		result = append(result, map[string]interface{}{
			"name":       name,
			"step_count": len(steps),
			"triggers":   []string{name},
		})
	}

	// Also check filesystem for yaml playbooks
	playbookDir := "playbooks"
	if entries, err := os.ReadDir(playbookDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
				result = append(result, map[string]interface{}{
					"name":      strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())),
					"file":      e.Name(),
					"type":      "yaml",
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"playbooks": result, "total": len(result)})
}

// ── Main ───────────────────────────────────────

func main() {
	port := os.Getenv("INCIDENT_RESPONSE_PORT")
	if port == "" {
		port = "8004"
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if req.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy", "service": "incident-response", "version": "1.0.0",
			"stats": stats,
		})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.Post("/incidents", createIncident)
	r.Get("/incidents", listIncidents)
	r.Get("/incidents/{id}", getIncident)
	r.Post("/incidents/{id}/execute", executeIncidentPlaybook)
	r.Get("/playbooks", listPlaybooks)

	log.Printf("Incident Response SOAR Service starting on :%s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
