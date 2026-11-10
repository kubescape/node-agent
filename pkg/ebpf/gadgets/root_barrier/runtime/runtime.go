// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the root_barrier gadget: it writes
// the covered cgroups and refuses Ready until the barrier is attested.
package runtime

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/rootbarrier"
)

const (
	operatorName = "root-barrier"
	annotation   = "annotations.root-barrier"
	configKey    = "root-barrier/config"
	ownerKey     = "root-barrier/owner"
	coveredMap   = "covered_cgroups"
	// MaxCovered matches COVERED_CGROUPS_MAX in ../program.bpf.c.
	MaxCovered = 1024
)

// Cgroup is one bound cgroup v2 id. A nonzero ExemptMntns leaves tasks in
// that mount namespace uncovered (the runtime's setup work in the cgroup).
//
// Enforce marks a binding that can enforce (Strict). Only such a binding is
// covered by the barrier; an audit-only binding (Enforce false) is never
// judged, so the barrier never blocks it. Scope is exact by default: only
// tasks in the cgroup itself are covered, and a task of an enforcing binding
// in a descendant cgroup is a Strict fault (denied, counted). Subtree, an
// explicit per-binding extension that the caller reports in its status,
// covers descendant cgroups too; it needs Path (the cgroup v2 path, for its
// level), at most 16 levels below the root (COVERED_CGROUPS_LEVELS in
// ../program.bpf.c). The root cgroup cannot be bound.
type Cgroup struct {
	ID          uint64
	Path        string
	ExemptMntns uint64
	Enforce     bool
	Subtree     bool
}

// coveredValue matches struct covered_cgroup in ../program.bpf.c.
type coveredValue struct {
	ExemptMntns uint64
	Flags       uint32
	Reserved    uint32
}

const (
	coveredEnforce = 0x1 // COVERED_ENFORCE
	coveredSubtree = 0x2 // COVERED_SUBTREE
	// coveredLevels is COVERED_CGROUPS_LEVELS.
	coveredLevels = 16
	dropsMap      = "denial_drops"
)

// Config holds the cgroups covered from the start.
type Config struct {
	Initial []Cgroup
}

func WithConfig(config Config) gadgetcontext.Option {
	config.Initial = append([]Cgroup(nil), config.Initial...)
	return func(gc *gadgetcontext.GadgetContext) { gc.SetVar(configKey, config) }
}

// GetOwner returns the owner of a running instance.
func GetOwner(gc operators.GadgetContext) (*Owner, error) {
	value, _ := gc.GetVar(ownerKey)
	o, ok := value.(*Owner)
	if !ok {
		return nil, fmt.Errorf("root barrier owner is unavailable")
	}
	return o, nil
}

// Owner covers cgroups of one gadget instance. It writes the initial cgroups
// at Start and runs rootbarrier.Verify at Ready. A failed verification refuses
// Ready when an initial binding enforces, and refuses every later binding that
// enforces until a retried verification passes (Cover retries it). Audit-only
// bindings never depend on the barrier, but Health reports the failure, so
// the caller shows a degraded or NotReady condition instead of a silent Ready.
type Owner struct {
	mu                       sync.Mutex
	initial                  []Cgroup
	covered, counters, probe *ebpf.Map
	faults, drops            *ebpf.Map
	ready                    bool
	barrierErr               error
	// lastVerify is when Cover last retried the verification; verifying
	// is set while one runs (single flight).
	lastVerify time.Time
	verifying  bool
}

// verifyRetry is the shortest time between two retried verifications.
const verifyRetry = 10 * time.Second

func (o *Owner) Name() string { return operatorName }

func (o *Owner) Start(gc operators.GadgetContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for name, dst := range map[string]**ebpf.Map{coveredMap: &o.covered, rootbarrier.CountersMap: &o.counters,
		rootbarrier.ProbeMap: &o.probe, rootbarrier.FaultsMap: &o.faults, dropsMap: &o.drops} {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok || m == nil {
			return fmt.Errorf("missing BPF map %s", name)
		}
		*dst = m
	}
	if o.covered.Type() != ebpf.Hash || o.covered.KeySize() != 8 || o.covered.ValueSize() != 16 || o.covered.MaxEntries() != MaxCovered {
		return fmt.Errorf("invalid covered cgroup map layout")
	}
	for _, c := range o.initial {
		if err := o.cover(c); err != nil {
			return err
		}
	}
	return nil
}

// Ready refuses activation when an initial binding enforces and the barrier is
// not attached or does not deny.
func (o *Owner) Ready(gc operators.GadgetContext) error {
	err := rootbarrier.Verify(gc, rootbarrier.Hooks)
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil {
		for _, c := range o.initial {
			if c.Enforce {
				return err
			}
		}
	}
	o.barrierErr = err
	o.ready = true
	return nil
}

func (o *Owner) Stop(operators.GadgetContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ready = false
	o.covered = nil
	return nil
}

func (o *Owner) Close(gc operators.GadgetContext) error { return o.Stop(gc) }

// Cover adds or updates one cgroup.
func (o *Owner) Cover(c Cgroup) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.ready {
		return fmt.Errorf("root barrier is not ready")
	}
	if c.Enforce && o.barrierErr != nil {
		// Retry: a failure can be transient (for example a link walk
		// during another gadget's attach). It runs without the lock, one
		// at a time, at most every verifyRetry.
		if o.verifying || time.Since(o.lastVerify) < verifyRetry {
			return fmt.Errorf("enforcing binding refused: %w", o.barrierErr)
		}
		o.verifying, o.lastVerify = true, time.Now()
		counters, probe := o.counters, o.probe
		o.mu.Unlock()
		err := rootbarrier.VerifyMaps(counters, probe, rootbarrier.Hooks)
		o.mu.Lock()
		o.verifying = false
		if !o.ready {
			return fmt.Errorf("root barrier is not ready")
		}
		o.barrierErr = err
		if err != nil {
			return fmt.Errorf("enforcing binding refused: %w", err)
		}
	}
	return o.cover(c)
}

// Health returns the last verification error: the barrier is not attested,
// so no binding may count as Strict-protected. It is nil once a verification
// passed.
func (o *Owner) Health() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.ready {
		return fmt.Errorf("root barrier is not ready")
	}
	return o.barrierErr
}

// Faults returns the predicate faults (Strict faults denied, Audit faults
// allowed) since the instance started: witness counters for the caller's
// Ready or degraded status.
func (o *Owner) Faults() (map[rootbarrier.Fault]uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.faults == nil {
		return nil, fmt.Errorf("root barrier is not running")
	}
	return rootbarrier.Faults(o.faults)
}

// Drops returns the denial events dropped because the ring buffer was full.
// Each is a denial with no event.
func (o *Owner) Drops() (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.drops == nil {
		return 0, fmt.Errorf("root barrier is not running")
	}
	var perCPU []uint64
	if err := o.drops.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

func (o *Owner) cover(c Cgroup) error {
	if c.ID == 0 || c.ID == rootCgroupID() {
		return fmt.Errorf("covered cgroup requires a non-root cgroup v2 id")
	}
	if err := checkLevel(c); err != nil {
		return err
	}
	value := coveredValue{ExemptMntns: c.ExemptMntns}
	if c.Enforce {
		value.Flags |= coveredEnforce
	}
	if c.Subtree {
		value.Flags |= coveredSubtree
	}
	if err := o.covered.Put(c.ID, value); err != nil {
		return fmt.Errorf("writing covered cgroup: %w", err)
	}
	return nil
}

// Uncover removes one cgroup.
func (o *Owner) Uncover(id uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.covered == nil {
		return fmt.Errorf("root barrier is not running")
	}
	if err := o.covered.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("removing covered cgroup: %w", err)
	}
	return nil
}

// Denials returns the barrier's denial counters.
func (o *Owner) Denials() (map[rootbarrier.Op]uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.counters == nil {
		return nil, fmt.Errorf("root barrier is not running")
	}
	return rootbarrier.Denials(o.counters)
}

// cgroupLevel is the cgroup v2 level of a path ("/a/b" is 2).
func cgroupLevel(path string) int {
	return strings.Count(strings.Trim(path, "/"), "/") + 1
}

// cgroupRoot is the host cgroup v2 mount (replaced in tests).
var cgroupRoot = filepath.Join(host.HostRoot, "sys/fs/cgroup")

// checkLevel refuses an enforcing or subtree binding that the program would
// not see from its descendants: one with no path, a path that is not the
// cgroup's (the inode must be ID), or one deeper than COVERED_CGROUPS_LEVELS.
// Without it, a Strict binding would silently not cover a task that moved
// into a child cgroup.
func checkLevel(c Cgroup) error {
	if !c.Enforce && !c.Subtree {
		return nil
	}
	clean := filepath.Clean("/" + c.Path)
	if c.Path == "" || strings.Contains(c.Path, "..") || clean == "/" {
		return fmt.Errorf("an enforcing or subtree binding needs its cgroup v2 path")
	}
	if cgroupLevel(clean) > coveredLevels {
		return fmt.Errorf("an enforcing or subtree binding must be at most %d cgroup levels below the root", coveredLevels)
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(cgroupRoot, clean), &st); err != nil || st.Ino != c.ID {
		return fmt.Errorf("cgroup path %s is not cgroup %d", clean, c.ID)
	}
	return nil
}

// rootCgroupID is the id of the cgroup v2 root: the inode of its directory.
func rootCgroupID() uint64 {
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(host.HostRoot, "sys/fs/cgroup"), &st); err == nil {
		return st.Ino
	}
	return 1 // the kernfs root id
}

type operator struct{}

func New() operators.DataOperator            { return &operator{} }
func init()                                  { operators.RegisterDataOperator(New()) }
func (*operator) Name() string               { return operatorName }
func (*operator) Priority() int              { return 1 }
func (*operator) Init(*params.Params) error  { return nil }
func (*operator) GlobalParams() api.Params   { return nil }
func (*operator) InstanceParams() api.Params { return nil }

func (*operator) InstantiateDataOperator(gc operators.GadgetContext, _ api.ParamValues) (operators.DataOperatorInstance, error) {
	value, _ := gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	if !ok || !metadata.GetBool(annotation) {
		return nil, nil
	}
	value, _ = gc.GetVar(configKey)
	config, _ := value.(Config)
	if len(config.Initial) > MaxCovered {
		return nil, fmt.Errorf("too many covered cgroups")
	}
	o := &Owner{initial: config.Initial}
	gc.SetVar(ownerKey, o)
	return o, nil
}
