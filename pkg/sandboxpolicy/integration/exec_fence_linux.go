//go:build linux

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"

	rf "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
)

var _ sandboxpolicy.ExecFence = (*ExecFenceManager)(nil)
var _ igbackend.NativeChangeGuard = (*ExecFenceManager)(nil)
var _ igbackend.NativeBindingRetainer = (*ExecFenceManager)(nil)

type FenceGenerationAttester interface {
	AttestFenceGeneration(context.Context, sandboxpolicy.Binding, string) (uint64, error)
}
type execFenceKernel interface {
	PublishCensus(*os.File, uint64, uint64, rf.Mode, []rf.PodMember) (rf.PodRef, error)
	ReadPod(uint64) (rf.PodState, bool, error)
	RefenceChild(rf.PodRef, rf.ChildRef) (rf.PodRef, error)
	MoveChild(rf.PodRef, rf.ChildRef, uint64) (rf.PodRef, error)
	CommitPolicyWithdrawal(rf.PodRef, rf.ChildRef) (rf.PodRef, error)
	DeactivateExecScope(rf.PodRef) (rf.PodRef, error)
	Arm() error
	Snapshot() (rf.Snapshot, error)
	Close() error
}
type fenceBinding struct {
	pod      uint64
	child    rf.ChildRef
	revision string
	mode     rf.Mode
	desired  rf.Mode
}

// Native custody outlives current-census publication authority. A zero pod
// means the exact current native route never needed a fence child at capture.
type nativeFenceReceipt struct {
	pod   uint64
	child rf.ChildRef
}

// ExecFenceManager serializes census, native seals, and exact-generation handoff.
// A refusal is sticky for this process. Close never removes pins or lifts marks.
type ExecFenceManager struct {
	mu        sync.Mutex
	kernel    execFenceKernel
	refusal   error
	attester  FenceGenerationAttester
	validator igbackend.Validator
	open      func(sandboxpolicy.Binding) (*FenceCgroups, error)
	pods      map[uint64]rf.PodRef
	bindings  map[uint64]fenceBinding
	scope     map[uint64]bool
	unmarked  map[uint64]string
	native    map[uint64]*nativeFenceReceipt
	// Native mutation guards advance even if a child is already fenced
	// and the pinned row revision does not change.
	nativeEpoch uint64
	exitProbe   func() (fenceExitProbe, error)
	gcError     error
	gcCursor    uint64
}

func NewExecFenceManager(root, procRoot, cgroupRoot string) *ExecFenceManager {
	m := &ExecFenceManager{validator: igbackend.LinuxValidator{ProcRoot: procRoot, CgroupRoot: cgroupRoot}, pods: map[uint64]rf.PodRef{}, bindings: map[uint64]fenceBinding{}, scope: map[uint64]bool{}}
	m.exitProbe = func() (fenceExitProbe, error) { return openFenceExitProbe(cgroupRoot) }
	m.open = func(b sandboxpolicy.Binding) (*FenceCgroups, error) { return OpenFenceCgroups(cgroupRoot, b) }
	object, err := rf.Object()
	if err != nil {
		m.refusal = err
		return m
	}
	f, err := rf.Open(root, object)
	if err != nil {
		m.refusal = err
		return m
	}
	m.kernel = f
	_, m.refusal = f.Register()
	return m
}
func (m *ExecFenceManager) SetAttester(a FenceGenerationAttester) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attester = a
}
func (m *ExecFenceManager) Refusal() error { m.mu.Lock(); defer m.mu.Unlock(); return m.refusal }
func (m *ExecFenceManager) Snapshot() (rf.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refusal != nil {
		return rf.Snapshot{}, m.refusal
	}
	return m.kernel.Snapshot()
}
func (m *ExecFenceManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kernel == nil {
		return nil
	}
	err := m.kernel.Close()
	m.refusal = errors.New("exec fence manager closed")
	return err
}
func (m *ExecFenceManager) ArmAndVerify() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refusal != nil {
		return false, m.refusal
	}
	before, err := m.kernel.Snapshot()
	if err != nil {
		return false, err
	}
	if before.Retired {
		return false, nil
	}
	if err = m.kernel.Arm(); err != nil {
		return false, err
	}
	after, err := m.kernel.Snapshot()
	if err != nil {
		return false, err
	}
	if after.Retired {
		return false, nil
	}
	if after.LiveIncarnation != 0 {
		return false, errors.New("global fence arm not attested")
	}
	return true, nil
}

func fenceHash(v string) uint64 {
	s := sha256.Sum256([]byte(v))
	n := binary.LittleEndian.Uint64(s[:8])
	if n == 0 {
		return 1
	}
	return n
}
func fenceBindingID(b sandboxpolicy.Binding) uint64 {
	return fenceHash(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d", b.PodUID, b.Runtime, b.ContainerID, b.CgroupPath, b.CgroupID, b.PID, b.MountNamespace))
}

type preparedFenceChild struct {
	candidate sandboxpolicy.ExecFenceCandidate
	cgroups   *FenceCgroups
	lease     igbackend.Lease
	mode      rf.Mode
	identity  uint64
}

func (m *ExecFenceManager) Prepare(ctx context.Context, candidates []sandboxpolicy.ExecFenceCandidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refusal != nil {
		return m.refusal
	}
	m.unmarked = map[uint64]string{}
	// Current authority never flows from a prior census. Only backend-owned
	// native lifetimes retain exact teardown receipts across discovery loss.
	m.bindings = map[uint64]fenceBinding{}
	m.scope = map[uint64]bool{}
	groups := map[uint64][]preparedFenceChild{}
	for _, c := range candidates {
		lease, err := m.validator.Acquire(ctx, c.Binding)
		if err != nil {
			return err
		}
		defer lease.Close()
		cg, err := m.open(c.Binding)
		if err != nil {
			return err
		}
		defer cg.Close()
		mode := rf.Mode(0)
		if c.Known {
			if c.NoExec {
				mode = rf.Off
			} else {
				mode, err = igbackend.ExecFenceMode(c.Binding, c.Plan)
				if err != nil {
					return err
				}
			}
		}
		groups[cg.PodID] = append(groups[cg.PodID], preparedFenceChild{c, cg, lease, mode, fenceBindingID(c.Binding)})
	}
	m.reclaimExited(groups)
	for id, children := range groups {
		state, found, err := m.kernel.ReadPod(id)
		if err != nil {
			return err
		}
		uid := fenceHash(string(children[0].candidate.Binding.PodUID))
		if found && state.UIDHash != uid {
			return rf.ErrStalePod
		}
		scope := false
		fallback := rf.Audit
		for _, c := range children {
			scope = scope || c.candidate.Scope
			if c.candidate.MayStrict || c.mode == rf.Strict {
				fallback = rf.Strict
			}
		}
		// Historical Strict/unknown classifications cannot be silently weakened.
		if found && state.Fallback == rf.Strict {
			fallback = rf.Strict
		}
		if !scope && (!found || state.Inactive) {
			for _, c := range children {
				if !c.candidate.Known || c.mode != rf.Off {
					return errors.New("unscoped pod lacks authoritative Off census")
				}
				m.unmarked[c.identity] = c.candidate.Plan.Revision
				if native := m.native[c.identity]; native != nil {
					*native = nativeFenceReceipt{}
				}
			}
			continue
		}
		m.scope[id] = scope
		members := []rf.PodMember{}
		prepared := map[uint64]fenceBinding{}
		for _, c := range children {
			if fenceHash(string(c.candidate.Binding.PodUID)) != uid {
				return rf.ErrStalePod
			}
			if err := c.lease.Check(); err != nil {
				return err
			}
			mode := c.mode
			for _, old := range state.Children {
				if old.ID == c.cgroups.ContainerID {
					if old.Identity != c.identity {
						return rf.ErrStalePod
					}
					if old.Mode != rf.Off && (mode == 0 || mode != old.Mode) {
						mode = old.Mode
					}
				}
			}
			// Unknown new children remain under the pod fallback, not invented Off.
			if mode == 0 {
				continue
			}
			members = append(members, rf.PodMember{Cgroup: c.cgroups.Container, Identity: c.identity, Mode: mode})
			prepared[c.identity] = fenceBinding{
				pod: id, child: rf.ChildRef{ID: c.cgroups.ContainerID, Identity: c.identity},
				revision: c.candidate.Plan.Revision, mode: mode, desired: c.mode,
			}
		}
		ref, err := m.kernel.PublishCensus(children[0].cgroups.Pod, uid, state.Revision, fallback, members)
		if err != nil {
			return err
		}
		m.pods[id] = ref
		for k, v := range prepared {
			m.bindings[k] = v
			if native := m.native[k]; native != nil {
				*native = nativeFenceReceipt{pod: v.pod, child: v.child}
			}
		}
	}
	return nil
}
func (m *ExecFenceManager) refence(b sandboxpolicy.Binding) error {
	if m.refusal != nil {
		return m.refusal
	}
	key := fenceBindingID(b)
	if _, unmarked := m.unmarked[key]; unmarked {
		return nil // authoritative current census proves no marked exec route
	}
	s, err := m.kernel.Snapshot()
	if err != nil {
		return err
	}
	// Only verified global arm or explicit retirement permits teardown without
	// a child mutation. Arbitrary errors never authorize native destruction.
	if s.LiveIncarnation == 0 {
		return nil
	}
	var receipt nativeFenceReceipt
	if v, ok := m.bindings[key]; ok {
		receipt = nativeFenceReceipt{pod: v.pod, child: v.child}
	} else if native := m.native[key]; native != nil {
		receipt = *native
		if receipt.pod == 0 {
			return nil // retained native-only binding never owned an exec child
		}
	} else {
		return errors.New("unclassified exec fence binding")
	}
	if gone, proofErr := m.bindingExited(receipt.child.ID); gone && proofErr == nil {
		return nil
	}
	ref, err := m.kernel.RefenceChild(m.pods[receipt.pod], receipt.child)
	if err == nil {
		m.pods[receipt.pod] = ref
	}
	return err
}
func (m *ExecFenceManager) Refence(_ context.Context, b sandboxpolicy.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refence(b)
}
func (m *ExecFenceManager) BeforeNativeChange(_ context.Context, b sandboxpolicy.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nativeEpoch == math.MaxUint64 {
		return fmt.Errorf("native fence mutation epoch exhausted")
	}
	if err := m.refence(b); err != nil {
		return err
	}
	m.nativeEpoch++
	return nil
}

// Native class is fixed for a live binding. Even a newly constructed native
// engine after restart must not commit a different class than the persistent
// fence. Refusing publication here preserves the predecessor's last good route.
func (m *ExecFenceManager) beforeReplace(key uint64, revision string) (fenceBinding, error) {
	if m.refusal != nil {
		return fenceBinding{}, m.refusal
	}
	if revision == "" {
		return fenceBinding{}, errors.New("empty native exec plan revision")
	}
	if unmarked, ok := m.unmarked[key]; ok && unmarked == revision {
		return fenceBinding{mode: rf.Off}, nil
	}
	v, ok := m.bindings[key]
	if !ok || v.revision != revision || v.desired == 0 {
		return fenceBinding{}, errors.New("native publication has no exact prepared exec classification")
	}
	if v.mode != v.desired {
		return fenceBinding{}, fmt.Errorf("native publication refused: exec fence has class %v, desired %v", v.mode, v.desired)
	}
	return v, nil
}

func (m *ExecFenceManager) BeforeReplace(_ context.Context, b sandboxpolicy.Binding, revision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.beforeReplace(fenceBindingID(b), revision)
	return err
}

func (m *ExecFenceManager) RetainNativeBinding(_ context.Context, b sandboxpolicy.Binding, revision string) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fenceBindingID(b)
	v, err := m.beforeReplace(key, revision)
	if err != nil {
		return nil, err
	}
	if m.native[key] != nil {
		return nil, errors.New("native fence custody already retained")
	}
	if m.native == nil {
		m.native = map[uint64]*nativeFenceReceipt{}
	}
	receipt := &nativeFenceReceipt{pod: v.pod, child: v.child}
	m.native[key] = receipt
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.native[key] == receipt {
			delete(m.native, key)
		}
	}, nil
}

func (m *ExecFenceManager) VerifyAndMove(ctx context.Context, b sandboxpolicy.Binding, revision string) error {
	key := fenceBindingID(b)
	m.mu.Lock()
	v, prepareErr := m.beforeReplace(key, revision)
	if prepareErr != nil || v.mode == rf.Off {
		m.mu.Unlock()
		return prepareErr
	}
	if m.attester == nil {
		err := errors.Join(errors.New("no native generation attester"), m.refence(b))
		m.mu.Unlock()
		return err
	}
	expectedPod, nativeEpoch, attester, validator := m.pods[v.pod], m.nativeEpoch, m.attester, m.validator
	// Backend mutation takes the native record lock before entering our
	// guard. Never call its attester while holding the manager lock.
	m.mu.Unlock()

	lease, err := validator.Acquire(ctx, b)
	var generation uint64
	if err == nil {
		defer lease.Close()
		generation, err = attester.AttestFenceGeneration(ctx, b, revision)
		if err == nil {
			if generation == 0 {
				err = errors.New("zero native generation")
			} else {
				err = lease.Check()
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refusal != nil {
		return errors.Join(err, m.refusal)
	}
	if m.bindings[key] != v || m.pods[v.pod] != expectedPod || m.nativeEpoch != nativeEpoch {
		// Do not replay the old witness or refence the successor's receipt.
		return errors.Join(err, errors.New("exec fence changed during native generation attestation"))
	}
	if err != nil {
		return errors.Join(err, m.refence(b))
	}
	ref, err := m.kernel.MoveChild(expectedPod, v.child, generation)
	if err != nil {
		return errors.Join(err, m.refence(b))
	}
	m.pods[v.pod] = ref
	return nil
}

func (m *ExecFenceManager) withdrawal(b sandboxpolicy.Binding) (uint64, fenceBinding, bool, error) {
	key := fenceBindingID(b)
	if m.refusal != nil {
		return key, fenceBinding{}, false, m.refusal
	}
	if _, unmarked := m.unmarked[key]; unmarked {
		return key, fenceBinding{}, false, nil
	}
	v, ok := m.bindings[key]
	if !ok || v.desired != rf.Off {
		return key, fenceBinding{}, false, errors.New("withdrawal lacks authoritative Off classification")
	}
	return key, v, v.mode != rf.Off, nil
}

func (m *ExecFenceManager) PrepareWithdrawal(_ context.Context, b sandboxpolicy.Binding) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, v, needed, err := m.withdrawal(b)
	if !needed || err != nil {
		return false, err
	}
	// Refence the exact inherited receipt even if its owner has already
	// stopped. Off rejects any BoundSections, regardless of incarnation.
	ref, err := m.kernel.RefenceChild(m.pods[v.pod], v.child)
	if err != nil {
		return false, err
	}
	m.pods[v.pod] = ref
	return true, nil
}

func (m *ExecFenceManager) Withdrawn(_ context.Context, b sandboxpolicy.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, v, needed, err := m.withdrawal(b)
	if !needed || err != nil {
		return err
	}
	ref, err := m.kernel.CommitPolicyWithdrawal(m.pods[v.pod], v.child)
	if err != nil {
		return err
	}
	m.pods[v.pod] = ref
	v.mode = rf.Off
	m.bindings[key] = v
	return nil
}
func (m *ExecFenceManager) Deactivate(_ context.Context, b sandboxpolicy.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refusal != nil {
		return m.refusal
	}
	if _, unmarked := m.unmarked[fenceBindingID(b)]; unmarked {
		return nil
	}
	v, ok := m.bindings[fenceBindingID(b)]
	if !ok {
		return nil
	}
	scope, known := m.scope[v.pod]
	if !known || scope {
		return errors.New("pod may still have exec policy scope")
	}
	ref, err := m.kernel.DeactivateExecScope(m.pods[v.pod])
	if err == nil {
		m.pods[v.pod] = ref
	}
	return err
}
