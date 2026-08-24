// Package rulestate holds short-lived, TTL-bounded markers that let a CEL rule
// remember a fact from one event and read it back when a later event arrives.
//
// The package deliberately knows nothing about CEL, rules or Kubernetes: it is a
// bounded map with expiry, so it stays unit-testable without an evaluator. The
// CEL bindings live in pkg/rulemanager/cel/libraries/state, and write-clause
// execution in pkg/rulemanager/statewrites.
package rulestate

import (
	"errors"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
)

var (
	// ErrScopeCapReached means this scope is at its entry cap. The write is
	// rejected -- never satisfied by evicting an existing entry, which would let
	// one workload silently disable detection for itself or a neighbour.
	ErrScopeCapReached = errors.New("rulestate: scope entry cap reached")
	// ErrGlobalCapReached means the node-wide ceiling is reached even after a sweep.
	ErrGlobalCapReached = errors.New("rulestate: global entry cap reached")
)

// Entry is one remembered fact.
//
// Process and Admission are mutually exclusive: node-agent entries carry a
// Process, operator entries carry an Admission. Both map straight onto
// armotypes.CorrelationEvidence, so store -> alert is a copy, not a translation.
type Entry struct {
	RuleID    string
	Name      string
	Scope     armotypes.StateScope
	ScopeID   string
	Key       string
	EventType armotypes.EventType

	// Timestamp is when the remembered event HAPPENED (see cel.ResolveEventTime),
	// not when it was observed. Ordering guards compare against it.
	Timestamp time.Time
	ExpiresAt time.Time

	Process   *armotypes.Process
	Admission *armotypes.AdmissionEvidence
	Value     map[string]any
}

func (e *Entry) expired(now time.Time) bool { return now.After(e.ExpiresAt) }

// Config bounds the store. Caps are the anti-abuse mechanism.
type Config struct {
	Enabled bool `mapstructure:"enabled"`
	// MaxSize is the node-wide ceiling, a backstop above the per-scope caps.
	MaxSize int `mapstructure:"maxSize"`
	// MaxEntriesPerContainer bounds one container, and also one pod bucket --
	// see Store.scopeCap for why pod scope shares this cap rather than the
	// larger one.
	MaxEntriesPerContainer int `mapstructure:"maxEntriesPerContainer"`
	// MaxEntriesForHost bounds the c:__host__ bucket, which holds the whole
	// node's process space rather than one workload, and never receives a
	// container-removal purge -- so it needs a larger cap and relies on TTL.
	MaxEntriesForHost int           `mapstructure:"maxEntriesForHost"`
	MaxTTL            time.Duration `mapstructure:"maxTtl"`
	SweepInterval     time.Duration `mapstructure:"sweepInterval"`
	AncestorMaxDepth  int           `mapstructure:"ancestorMaxDepth"`
}

// Metrics is the observability surface. There is deliberately no per-read
// counter: reads are on the hot path.
type Metrics interface {
	ReportStateWrite(ruleID, result string)
	ReportStateWriteRejected(ruleID, reason string)
	ReportStateExpired(n int)
	ReportStatePurged(n int)
	ReportStateEntries(scope string, n int)
}

type NoopMetrics struct{}

func (NoopMetrics) ReportStateWrite(string, string)         {}
func (NoopMetrics) ReportStateWriteRejected(string, string) {}
func (NoopMetrics) ReportStateExpired(int)                  {}
func (NoopMetrics) ReportStatePurged(int)                   {}
func (NoopMetrics) ReportStateEntries(string, int)          {}

const hostScopeSuffix = "__host__"

// ContainerScopeID maps a container ID to its bucket. The empty container ID is
// a host / cgroup-0 process, which gets an explicit pseudo-container bucket --
// without the type prefix it would collide with node scope, whose ID is also "".
func ContainerScopeID(containerID string) string {
	if containerID == "" {
		return "c:" + hostScopeSuffix
	}
	return "c:" + containerID
}

func HostScopeID() string               { return "c:" + hostScopeSuffix }
func NodeScopeID() string               { return "n:" }
func PodScopeID(ns, pod string) string  { return "p:" + ns + "/" + pod }
func IsHostScopeID(scopeID string) bool { return scopeID == HostScopeID() }
