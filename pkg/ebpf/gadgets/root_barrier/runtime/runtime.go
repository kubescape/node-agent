// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the root_barrier gadget: it writes
// the covered cgroups and refuses Ready until the barrier is attested.
package runtime

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

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

// Cgroup is one covered cgroup v2 id. A nonzero ExemptMntns leaves tasks in
// that mount namespace uncovered (the runtime's setup work in the cgroup). The
// cgroup must be at most 16 levels below the root (COVERED_CGROUPS_LEVELS in
// ../program.bpf.c) and must not be the root.
type Cgroup struct {
	ID          uint64
	ExemptMntns uint64
}

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
// at Start and reports Ready only after rootbarrier.Verify.
type Owner struct {
	mu       sync.Mutex
	initial  []Cgroup
	covered  *ebpf.Map
	counters *ebpf.Map
	ready    bool
}

func (o *Owner) Name() string { return operatorName }

func (o *Owner) Start(gc operators.GadgetContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for name, dst := range map[string]**ebpf.Map{coveredMap: &o.covered, rootbarrier.CountersMap: &o.counters} {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok || m == nil {
			return fmt.Errorf("missing BPF map %s", name)
		}
		*dst = m
	}
	if o.covered.Type() != ebpf.Hash || o.covered.KeySize() != 8 || o.covered.ValueSize() != 8 || o.covered.MaxEntries() != MaxCovered {
		return fmt.Errorf("invalid covered cgroup map layout")
	}
	for _, c := range o.initial {
		if err := o.cover(c); err != nil {
			return err
		}
	}
	return nil
}

// Ready refuses activation when the barrier is not attached or does not deny.
func (o *Owner) Ready(gc operators.GadgetContext) error {
	if err := rootbarrier.Verify(gc); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
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
	return o.cover(c)
}

func (o *Owner) cover(c Cgroup) error {
	if c.ID == 0 || c.ID == rootCgroupID() {
		return fmt.Errorf("covered cgroup requires a non-root cgroup v2 id")
	}
	if err := o.covered.Put(c.ID, c.ExemptMntns); err != nil {
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
