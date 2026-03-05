// Package soar implements a Security Orchestration, Automation, and Response
// engine with YAML-defined playbooks supporting sequential, parallel, and
// conditional execution of response actions.
package soar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ──────────────────────────────────────────────
// Playbook YAML schema
// ──────────────────────────────────────────────

// Playbook is the top-level playbook definition.
type Playbook struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	Triggers    []TriggerDef    `yaml:"triggers"`
	Variables   map[string]any  `yaml:"variables,omitempty"`
	Steps       []Step          `yaml:"steps"`
	OnFailure   []Step          `yaml:"on_failure,omitempty"`
}

// TriggerDef defines when a playbook fires.
type TriggerDef struct {
	Type       string            `yaml:"type"`    // alert_type, severity, schedule
	Conditions map[string]string `yaml:"conditions,omitempty"`
}

// Step is a single playbook action.
type Step struct {
	Name      string         `yaml:"name"`
	Action    string         `yaml:"action"`    // isolate_host, block_ip, enrich_ioc, notify, run_script, snapshot_forensic, quarantine_file
	Params    map[string]any `yaml:"params,omitempty"`
	Parallel  []Step         `yaml:"parallel,omitempty"`  // Run sub-steps in parallel
	Condition string         `yaml:"condition,omitempty"` // CEL-like expression
	Timeout   string         `yaml:"timeout,omitempty"`
	OnError   string         `yaml:"on_error,omitempty"`  // continue, abort, retry
}

// ──────────────────────────────────────────────
// Action types (built-in)
// ──────────────────────────────────────────────

type ActionFunc func(ctx context.Context, params map[string]any) (map[string]any, error)

// ActionRegistry holds all registered response actions.
type ActionRegistry struct {
	mu      sync.RWMutex
	actions map[string]ActionFunc
}

func NewActionRegistry() *ActionRegistry {
	r := &ActionRegistry{actions: make(map[string]ActionFunc)}
	r.registerBuiltins()
	return r
}

func (r *ActionRegistry) Register(name string, fn ActionFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions[name] = fn
}

func (r *ActionRegistry) Get(name string) (ActionFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.actions[name]
	return fn, ok
}

func (r *ActionRegistry) registerBuiltins() {
	r.Register("isolate_host", actionIsolateHost)
	r.Register("block_ip", actionBlockIP)
	r.Register("enrich_ioc", actionEnrichIOC)
	r.Register("notify", actionNotify)
	r.Register("run_script", actionRunScript)
	r.Register("snapshot_forensic", actionSnapshotForensic)
	r.Register("quarantine_file", actionQuarantineFile)
}

// ── Built-in action stubs ──────────────────────

func actionIsolateHost(_ context.Context, p map[string]any) (map[string]any, error) {
	host, _ := p["host"].(string)
	log.Printf("[SOAR] Isolating host: %s", host)
	// In production: call EDR API (CrowdStrike, SentinelOne, etc.)
	return map[string]any{"isolated": host, "status": "success"}, nil
}

func actionBlockIP(_ context.Context, p map[string]any) (map[string]any, error) {
	ip, _ := p["ip"].(string)
	log.Printf("[SOAR] Blocking IP: %s", ip)
	return map[string]any{"blocked": ip, "firewall": "applied"}, nil
}

func actionEnrichIOC(_ context.Context, p map[string]any) (map[string]any, error) {
	ioc, _ := p["ioc"].(string)
	log.Printf("[SOAR] Enriching IOC: %s", ioc)
	return map[string]any{"ioc": ioc, "reputation": "malicious", "source": "VirusTotal"}, nil
}

func actionNotify(_ context.Context, p map[string]any) (map[string]any, error) {
	channel, _ := p["channel"].(string)
	message, _ := p["message"].(string)
	log.Printf("[SOAR] Notify [%s]: %s", channel, message)
	return map[string]any{"notified": channel}, nil
}

func actionRunScript(_ context.Context, p map[string]any) (map[string]any, error) {
	script, _ := p["script"].(string)
	log.Printf("[SOAR] Running script: %s", script)
	return map[string]any{"script": script, "exit_code": 0}, nil
}

func actionSnapshotForensic(_ context.Context, p map[string]any) (map[string]any, error) {
	host, _ := p["host"].(string)
	log.Printf("[SOAR] Forensic snapshot of host: %s", host)
	return map[string]any{"snapshot_id": fmt.Sprintf("snap-%s-%d", host, time.Now().Unix())}, nil
}

func actionQuarantineFile(_ context.Context, p map[string]any) (map[string]any, error) {
	path, _ := p["path"].(string)
	log.Printf("[SOAR] Quarantining file: %s", path)
	return map[string]any{"quarantined": path}, nil
}

// ──────────────────────────────────────────────
// Playbook Engine
// ──────────────────────────────────────────────

// ExecutionResult captures the outcome of a playbook run.
type ExecutionResult struct {
	PlaybookName string                   `json:"playbook_name"`
	StartedAt    time.Time                `json:"started_at"`
	CompletedAt  time.Time                `json:"completed_at"`
	Status       string                   `json:"status"` // success, partial, failed
	StepResults  []StepResult             `json:"step_results"`
}

type StepResult struct {
	StepName string         `json:"step_name"`
	Action   string         `json:"action"`
	Status   string         `json:"status"`
	Output   map[string]any `json:"output,omitempty"`
	Error    string         `json:"error,omitempty"`
	Duration time.Duration  `json:"duration"`
}

// PlaybookEngine loads and executes YAML playbooks.
type PlaybookEngine struct {
	registry  *ActionRegistry
	playbooks map[string]*Playbook
	mu        sync.RWMutex
}

func NewPlaybookEngine() *PlaybookEngine {
	return &PlaybookEngine{
		registry:  NewActionRegistry(),
		playbooks: make(map[string]*Playbook),
	}
}

// LoadFromFile loads a playbook YAML file.
func (e *PlaybookEngine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read playbook %s: %w", path, err)
	}
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return fmt.Errorf("parse playbook %s: %w", path, err)
	}
	e.mu.Lock()
	e.playbooks[pb.Name] = &pb
	e.mu.Unlock()
	log.Printf("[SOAR] Loaded playbook: %s (%d steps)", pb.Name, len(pb.Steps))
	return nil
}

// Execute runs a named playbook with the given alert context.
func (e *PlaybookEngine) Execute(ctx context.Context, name string, alertCtx map[string]any) (*ExecutionResult, error) {
	e.mu.RLock()
	pb, ok := e.playbooks[name]
	e.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("playbook %q not found", name)
	}

	result := &ExecutionResult{
		PlaybookName: name,
		StartedAt:    time.Now(),
		Status:       "success",
	}

	for _, step := range pb.Steps {
		sr := e.executeStep(ctx, step, alertCtx)
		result.StepResults = append(result.StepResults, sr)
		if sr.Status == "failed" && step.OnError != "continue" {
			result.Status = "failed"
			// Run on_failure steps
			for _, failStep := range pb.OnFailure {
				fsr := e.executeStep(ctx, failStep, alertCtx)
				result.StepResults = append(result.StepResults, fsr)
			}
			break
		}
	}

	result.CompletedAt = time.Now()
	return result, nil
}

func (e *PlaybookEngine) executeStep(ctx context.Context, step Step, alertCtx map[string]any) StepResult {
	start := time.Now()
	sr := StepResult{StepName: step.Name, Action: step.Action}

	// Handle parallel sub-steps
	if len(step.Parallel) > 0 {
		sr.Action = "parallel"
		var wg sync.WaitGroup
		subResults := make([]StepResult, len(step.Parallel))
		for i, sub := range step.Parallel {
			wg.Add(1)
			go func(idx int, s Step) {
				defer wg.Done()
				subResults[idx] = e.executeStep(ctx, s, alertCtx)
			}(i, sub)
		}
		wg.Wait()
		sr.Status = "success"
		for _, sub := range subResults {
			if sub.Status == "failed" {
				sr.Status = "partial"
			}
		}
		sr.Duration = time.Since(start)
		return sr
	}

	// Apply timeout
	execCtx := ctx
	if step.Timeout != "" {
		if d, err := time.ParseDuration(step.Timeout); err == nil {
			var cancel context.CancelFunc
			execCtx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
		}
	}

	// Resolve params with alert context
	params := resolveParams(step.Params, alertCtx)

	fn, ok := e.registry.Get(step.Action)
	if !ok {
		sr.Status = "failed"
		sr.Error = fmt.Sprintf("unknown action %q", step.Action)
		sr.Duration = time.Since(start)
		return sr
	}

	output, err := fn(execCtx, params)
	if err != nil {
		sr.Status = "failed"
		sr.Error = err.Error()
	} else {
		sr.Status = "success"
		sr.Output = output
	}
	sr.Duration = time.Since(start)
	return sr
}

// MatchPlaybooks returns all playbooks whose triggers match the alert.
func (e *PlaybookEngine) MatchPlaybooks(alert map[string]any) []string {
	var matched []string
	e.mu.RLock()
	defer e.mu.RUnlock()

	alertType, _ := alert["alert_type"].(string)
	severity, _ := alert["severity"].(string)

	for name, pb := range e.playbooks {
		for _, t := range pb.Triggers {
			if t.Conditions["alert_type"] != "" && t.Conditions["alert_type"] == alertType {
				matched = append(matched, name)
				break
			}
			if t.Conditions["severity"] != "" && t.Conditions["severity"] == severity {
				matched = append(matched, name)
				break
			}
		}
	}
	return matched
}

// resolveParams replaces {{.field}} templates with alert context values.
func resolveParams(params map[string]any, ctx map[string]any) map[string]any {
	resolved := make(map[string]any, len(params))
	for k, v := range params {
		if s, ok := v.(string); ok {
			// Simple template: {{.host}} → ctx["host"]
			if len(s) > 4 && s[:3] == "{{." && s[len(s)-2:] == "}}" {
				key := s[3 : len(s)-2]
				if cv, ok := ctx[key]; ok {
					resolved[k] = cv
					continue
				}
			}
		}
		resolved[k] = v
	}
	return resolved
}

// ToJSON serializes an execution result.
func (r *ExecutionResult) ToJSON() string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}
