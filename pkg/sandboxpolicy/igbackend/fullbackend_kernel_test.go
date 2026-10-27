package igbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	orasoci "oras.land/oras-go/v2/content/oci"
)

// TestFullBackendContainerdKernel uses the production FullBackend, native OCI
// engine and authenticated ContainerdFullSource. Provision ONLY on a disposable
// supported-kernel VM, not a shared/production node:
//
//   - immutable image contains static testdata/fullbackend-helper.c binary as
//     /probe/init, /probe/role and /probe/target-{0..12};
//   - exact 64-hex container ID, k8s.io, runc-v2, overlayfs, private PID/mount
//     namespaces, supported canonicalRootSeccomp and capability/root barriers;
//   - start the task as /probe/init --serve, no other live task in its cgroup;
//   - IG_FULL_BACKEND_KERNEL_TEST=1, IG_IMAGE_EVIDENCE_CONTAINER_ID and optionally
//     IG_IMAGE_EVIDENCE_SOCKET; IG_FULL_BACKEND_OBJECT and IG_FULL_BACKEND_METADATA
//     point to the matching locally built persistent-owner object/metadata.
//
// FIFOs are created in the task's writable upper root and accessed via its pinned
// host PID, not bind-mounted helper exemptions. Runtime/container identity and
// image origins are obtained from the real trusted containerd connection. This
// fixture does not create/delete containers. It proves native public receiver
// delivery, not the separate Kubernetes selection/controller or private exporter.
func TestFullBackendContainerdKernel(t *testing.T) {
	if os.Getenv("IG_FULL_BACKEND_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable combined kernel fixture opt-in required")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	socket := os.Getenv("IG_IMAGE_EVIDENCE_SOCKET")
	if socket == "" {
		socket = "/run/containerd/containerd.sock"
	}
	id := os.Getenv("IG_IMAGE_EVIDENCE_CONTAINER_ID")
	require.True(t, fullContainerID(id))
	source, err := NewContainerdFullSource(socket, "/", "/proc", "/sys/fs/cgroup", ImageIndexLimits{})
	require.NoError(t, err)
	rt := local.New()
	require.NoError(t, rt.Init(nil))
	var backend *FullBackend
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if backend != nil {
			if err := backend.Close(cleanup); err != nil {
				t.Errorf("retaining native resources after failed cleanup: %v", err)
				return
			}
		}
		require.NoError(t, source.Close())
		require.NoError(t, rt.Close())
	}()
	evidence, err := source.source.Evidence(ctx, id)
	require.NoError(t, err)
	require.Equal(t, []string{"/probe/init", "--serve"}, evidence.Spec.Process.Args, "fixture must be the authenticated init, not a runtime exec helper")
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", evidence.PID))
	require.NoError(t, err)
	var cg string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "0::") {
			require.Empty(t, cg)
			cg = strings.TrimPrefix(line, "0::")
		}
	}
	require.NotEmpty(t, cg)
	require.NotEqual(t, "/", cg)
	var cgroup, mountns unix.Stat_t
	require.NoError(t, unix.Stat("/sys/fs/cgroup"+cg, &cgroup))
	require.NoError(t, unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", evidence.PID), &mountns))
	name := os.Getenv("IG_FULL_BACKEND_CONTAINER_NAME")
	if name == "" {
		name = "app"
	}
	binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: id, ContainerName: name, PodUID: types.UID(evidence.PodUID), Namespace: evidence.PodNamespace, PID: evidence.PID, CgroupID: cgroup.Ino, CgroupPath: cg, MountNamespace: mountns.Ino}
	control, err := openFullBackendControl(ctx, evidence.PID)
	require.NoError(t, err)
	defer control.close()
	code, err := control.command(ctx, "PING")
	require.NoError(t, err)
	require.Zero(t, code)
	// Prove the exact CRI exec invocation works before policy activation, so a
	// later refusal cannot be attributed to a malformed CLI or unavailable RPC.
	criExec := func() ([]byte, error) {
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return exec.CommandContext(attempt, "/usr/local/bin/crictl", "--runtime-endpoint", "unix://"+socket, "exec", "--sync", id, "/probe/target-11", "--target", "--token=ok").CombinedOutput()
	}
	output, err := criExec()
	require.NoError(t, err, "baseline actual CRI exec: %s", output)
	store, image := fullBackendKernelImage(t)
	budget, err := fullruntime.NewBudget(fullruntime.BudgetLimits{Owners: 1, MapPayloadBytes: fullruntime.OwnerMapPayloadLimit, ProgramInstructions: fullruntime.OwnerInstructionLimit, HistoryEntries: fullruntime.OwnerHistoryLimit})
	require.NoError(t, err)
	telemetry := &fullBackendKernelReceiver{events: make(chan sandboxpolicy.Verdict, 256)}
	failures := make(chan error, 64)
	onError := func(err error) {
		select {
		case failures <- err:
		default:
			telemetry.lost.Add(1)
		}
	}
	// The observer-enrichment operator is intentionally empty. It provides no
	// runtime facts or lease authority; the real source/owner do all admission.
	engine, err := NewNativeFullEngine(rt, simple.New("fixture-no-observer-enrichment"), store, image, "/sys/fs/cgroup", budget, onError)
	require.NoError(t, err)
	backend, err = NewFull(engine, source, telemetry, onError)
	require.NoError(t, err)
	plan := fullBackendKernelPlan("plan-1", "agent", 0, 1, name)
	result, err := backend.Replace(ctx, binding, plan)
	require.NoError(t, err)
	require.True(t, result.Committed)
	require.False(t, result.ProtectionUnconfirmed)
	first := backend.records[key(binding)].instance
	generation := first.Generation()
	require.NotZero(t, generation)
	epoch := first.Epochs()["fixture-policy-uid"]
	require.Equal(t, generation, epoch)
	require.Equal(t, uint64(1), budget.Usage().Owners)
	run := func(command string, want int) {
		t.Helper()
		code, err := control.command(ctx, command)
		require.NoError(t, err)
		require.Equal(t, want, code, command)
	}
	// The unflagged application shm bind is accepted only with the verified
	// restrictive runtime-device/caps/NNP matrix. Test actual unknown devices,
	// not merely lack of CAP_MKNOD (a sibling may create the nodes).
	proveFullBackendDeviceBarrier(t, ctx, control, evidence.PID)
	// Thirteen authored paths in one matching rule, every real path exercised.
	for i := 0; i < 13; i++ {
		want := 0
		if i == 0 || i == 12 {
			want = 77
		}
		run(fmt.Sprintf("RUN %d", i), want)
	}
	run("CHAIN", 0) // setRole on /probe/role, then real fork inheritance into target12
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-1", "/probe/target-0", api.ActionDeny, false, "deny-control")
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-1", "/probe/target-1", api.ActionDeny, true, "audit-control")
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-1", "/probe/target-12", api.ActionAllow, false, "inherited-worker")
	// Add another allowed attempt after draining earlier telemetry so its event is
	// observed explicitly rather than merely inferred from absence of an error.
	run("RUN 11", 0)
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-1", "/probe/target-11", api.ActionAllow, false, "root-paths")
	plan = fullBackendKernelPlan("plan-2", "edited-root-must-not-reset", 2, 3, name)
	result, err = backend.Replace(ctx, binding, plan)
	require.NoError(t, err)
	require.True(t, result.Committed)
	require.False(t, result.ProtectionUnconfirmed)
	require.Same(t, first, backend.records[key(binding)].instance)
	require.Greater(t, first.Generation(), generation)
	generation = first.Generation()
	require.Equal(t, epoch, first.Epochs()["fixture-policy-uid"])
	run("RUN 0", 0)
	run("RUN 2", 77)
	run("RUN 3", 0)
	run("RUN 12", 77)
	run("CHAIN", 0)
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-2", "/probe/target-2", api.ActionDeny, false, "deny-control")
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-2", "/probe/target-3", api.ActionDeny, true, "audit-control")
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-2", "/probe/target-12", api.ActionAllow, false, "inherited-worker")
	// Same revision re-attests without map-owner replacement or generation churn.
	result, err = backend.Replace(ctx, binding, plan)
	require.NoError(t, err)
	require.True(t, result.Committed)
	require.Equal(t, generation, first.Generation())
	rejected := fullBackendKernelPlan("too-large", "agent", 4, 5, name)
	rejected.Policies[0].Exec.Rules = nil
	for i := 0; i < fullpolicy.MaxRules+1; i++ {
		rejected.Policies[0].Exec.Rules = append(rejected.Policies[0].Exec.Rules, api.ExecRule{Rule: api.Rule{Name: fmt.Sprintf("excess-%d", i), Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/probe/target-2"}}}})
	}
	result, err = backend.Replace(ctx, binding, rejected)
	require.Error(t, err)
	require.False(t, result.Committed)
	require.False(t, result.ProtectionUnconfirmed)
	require.Equal(t, generation, first.Generation())
	require.Same(t, first, backend.records[key(binding)].instance)
	run("RUN 2", 77)
	expectFullBackendEvent(t, ctx, telemetry, failures, "plan-2", "/probe/target-2", api.ActionDeny, false, "deny-control")
	// Exercise the complete four-word match bitmap at the documented rule
	// boundary, not only a beyond-eight-path authoring example.
	capacity := fullBackendKernelPlan("capacity-256", "capacity-root-edit", 2, 3, name)
	baseRules := len(capacity.Policies[0].Exec.Rules)
	for i := baseRules; i < fullpolicy.MaxRules; i++ {
		capacity.Policies[0].Exec.Rules = append(capacity.Policies[0].Exec.Rules, api.ExecRule{Rule: api.Rule{Name: fmt.Sprintf("capacity-%03d", i), Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/probe/target-11"}}}})
	}
	result, err = backend.Replace(ctx, binding, capacity)
	require.NoError(t, err)
	require.True(t, result.Committed)
	require.False(t, result.ProtectionUnconfirmed)
	require.Same(t, first, backend.records[key(binding)].instance)
	require.Equal(t, epoch, first.Epochs()["fixture-policy-uid"])
	run("RUN 11", 0)
	boundary := expectFullBackendEvent(t, ctx, telemetry, failures, "capacity-256", "/probe/target-11", api.ActionAllow, false, "")
	require.Len(t, boundary.Matches, fullpolicy.MaxRules-baseRules+1)
	require.Equal(t, "capacity-255", boundary.Matches[len(boundary.Matches)-1].Name)
	t.Logf("actual %d-rule boundary emitted %d matches including bitmap bit255", fullpolicy.MaxRules, len(boundary.Matches))
	result, err = backend.Replace(ctx, binding, plan)
	require.NoError(t, err)
	require.True(t, result.Committed)
	require.False(t, result.ProtectionUnconfirmed)
	generation = first.Generation()
	require.Equal(t, epoch, first.Epochs()["fixture-policy-uid"])
	if os.Getenv("IG_FULL_BACKEND_RUNTIME_OUTAGE_TEST") == "1" {
		// This separate opt-in controls only the owned disposable VM daemon.
		// Runtime transport loss must not discard frozen last-good enforcement.
		service := func(action string) error {
			attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			out, err := exec.CommandContext(attempt, "systemctl", action, "containerd").CombinedOutput()
			if err != nil {
				return fmt.Errorf("containerd %s: %w: %s", action, err, out)
			}
			return nil
		}
		require.NoError(t, service("stop"))
		defer func() { require.NoError(t, service("start")) }()
		result, err = backend.Replace(ctx, binding, plan)
		require.Error(t, err)
		require.True(t, result.Committed)
		require.True(t, result.ProtectionUnconfirmed)
		require.Equal(t, generation, first.Generation())
		run("RUN 11", 0)
		run("RUN 2", 77)
		require.NoError(t, service("start"))
		var recoveryErr error
		require.Eventually(t, func() bool {
			result, recoveryErr = backend.Replace(ctx, binding, plan)
			return recoveryErr == nil && result.Committed && !result.ProtectionUnconfirmed
		}, 20*time.Second, 100*time.Millisecond, "same-owner trusted runtime re-attestation must recover: %v", recoveryErr)
		require.Same(t, first, backend.records[key(binding)].instance)
		require.Equal(t, generation, first.Generation())
		require.Equal(t, epoch, first.Epochs()["fixture-policy-uid"])
		t.Logf("actual containerd stop/start recovered same owner generation=%d epoch=%d with last-good enforcement intact", generation, epoch)
	}
	// Runtime helpers receive no inferred exemption. The same real CRI exec
	// that succeeded before activation must now be refused by strict policy.
	owner := first.(*nativeFullInstance).owner.(*fullruntime.Owner)
	before, err := owner.Diagnostics()
	require.NoError(t, err)
	require.Zero(t, before.Health.Faults)
	output, err = criExec()
	require.Error(t, err, "runtime helper unexpectedly bypassed strict policy: %s", output)
	var after fullruntime.OwnerDiagnostics
	require.Eventually(t, func() bool {
		var readErr error
		after, readErr = owner.Diagnostics()
		return readErr == nil && after.Admitted == 0 && after.Health.PendingBirths == 0
	}, 2*time.Second, 10*time.Millisecond, "completed rejected helper must not orphan a gate admission")
	// runc may hide kernel EPERM behind procReady-not-received. Correlate actual
	// owned kernel counters instead of accepting arbitrary RPC error text.
	require.True(t, after.Health.Faults != 0 || after.Health.GateDenials > before.Health.GateDenials, "need actual kernel refusal evidence, not unrelated CLI/RPC failure: %s", output)
	t.Logf("strict CRI helper refused: faults=%d gateDenialsDelta=%d admitted=%d: %s", after.Health.Faults, after.Health.GateDenials-before.Health.GateDenials, after.Admitted, strings.TrimSpace(string(output)))
	plan = fullBackendKernelPlan("plan-3", "must-not-redeem-lineage", 2, 3, name)
	result, err = backend.Replace(ctx, binding, plan)
	require.Same(t, first, backend.records[key(binding)].instance)
	require.Equal(t, epoch, first.Epochs()["fixture-policy-uid"])
	if after.Health.Faults != 0 {
		// Observed unproven ingress invalidates the owner. A new revision must
		// never clear structural faults or silently adopt the unknown helper.
		require.Equal(t, uint64(4), after.Health.Faults, "only lineage quarantine expected")
		require.Error(t, err)
		require.False(t, result.Committed)
		require.True(t, result.ProtectionUnconfirmed)
		require.Equal(t, generation, first.Generation())
	} else {
		// CLONE_INTO_CGROUP can be refused before a task exists. That is not
		// grounds to poison the legitimate parent's accepted role or owner.
		require.NoError(t, err)
		require.True(t, result.Committed)
		require.False(t, result.ProtectionUnconfirmed)
		require.Greater(t, first.Generation(), generation)
		generation = first.Generation()
		run("RUN 11", 0)
		run("RUN 2", 77)
		expectFullBackendEvent(t, ctx, telemetry, failures, "plan-3", "/probe/target-11", api.ActionAllow, false, "root-paths")
		expectFullBackendEvent(t, ctx, telemetry, failures, "plan-3", "/probe/target-2", api.ActionDeny, false, "deny-control")
	}
	kernelStats, err := backend.KernelEventStats(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), kernelStats.OwnedInstances)
	require.Zero(t, kernelStats.OwnedUnavailable)
	require.Zero(t, kernelStats.RetiredInstances)
	require.Greater(t, kernelStats.Owned.Submitted, uint64(0))
	require.Zero(t, kernelStats.Owned.Lost)
	withdrawn, err := backend.Withdraw(ctx, binding)
	require.NoError(t, err)
	require.True(t, withdrawn.Committed)
	require.Zero(t, budget.Usage().Owners)
	require.Empty(t, backend.records)
	finalStats, err := backend.KernelEventStats(ctx)
	require.NoError(t, err)
	require.Zero(t, finalStats.OwnedInstances)
	require.Equal(t, uint64(1), finalStats.RetiredInstances)
	require.Zero(t, finalStats.RetiredUnavailable)
	require.GreaterOrEqual(t, finalStats.Retired.Submitted, kernelStats.Owned.Submitted)
	require.Zero(t, finalStats.Retired.Lost)
	t.Logf("actual kernel per-CPU event counters survived withdrawal: submitted=%d ringLost=%d observationErrors=%d", finalStats.Retired.Submitted, finalStats.Retired.Lost, finalStats.Retired.ObservationErrors)
	run("RUN 2", 0)
	run("RUN 12", 0)
	require.Zero(t, telemetry.lost.Load(), "bounded test telemetry overflow")
	select {
	case err := <-failures:
		t.Fatalf("native telemetry error: %v", err)
	default:
	}
	t.Logf("combined persistent backend proved: container=%s pid=%d cgroup=%d epoch=%d generation=%d 13-paths real deny/audit/reload/roles/rejection/withdrawal", id, binding.PID, binding.CgroupID, epoch, generation)
}

type fullBackendKernelReceiver struct {
	backlog []sandboxpolicy.Verdict
	events  chan sandboxpolicy.Verdict
	lost    atomic.Uint64
}

func (r *fullBackendKernelReceiver) ReportVerdict(_ context.Context, v sandboxpolicy.Verdict) error {
	select {
	case r.events <- v:
	default:
		r.lost.Add(1)
	}
	return nil
}
func expectFullBackendEvent(t *testing.T, ctx context.Context, receiver *fullBackendKernelReceiver, failures <-chan error, revision, path string, action api.Action, audit bool, rule string) sandboxpolicy.Verdict {
	t.Helper()
	check := func(v sandboxpolicy.Verdict) {
		require.Equal(t, action, v.Verdict)
		require.Equal(t, audit, v.WouldDeny)
		require.Equal(t, rule, v.Rule)
		require.True(t, v.MatchesComplete)
		require.Equal(t, "matching_rule", v.Reason)
		require.NotZero(t, v.CgroupID)
		require.NotZero(t, v.PID)
		require.Equal(t, os.Getenv("IG_IMAGE_EVIDENCE_CONTAINER_ID"), v.ContainerID)
		require.NotZero(t, v.BindingPID)
		require.NotZero(t, v.MountNamespace)
		require.Len(t, v.PolicySet, 1)
		require.Equal(t, types.UID("fixture-policy-uid"), v.PolicySet[0].Policy.UID)
		require.Nil(t, v.UID)
		require.Nil(t, v.Argv)
		require.Nil(t, v.FromImage, "do not invent unreported predicate facts")
	}
	matches := func(v sandboxpolicy.Verdict) bool {
		return v.Revision == revision && v.TargetPath == path && v.Rule == rule
	}
	for i, v := range receiver.backlog {
		if matches(v) {
			receiver.backlog = append(receiver.backlog[:i], receiver.backlog[i+1:]...)
			check(v)
			return v
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("missing verdict revision=%s path=%s rule=%s: %v", revision, path, rule, ctx.Err())
		case err := <-failures:
			t.Fatalf("native telemetry error: %v", err)
		case v := <-receiver.events:
			if matches(v) {
				check(v)
				return v
			}
			require.Less(t, len(receiver.backlog), 256, "bounded fixture event backlog")
			receiver.backlog = append(receiver.backlog, v)
		}
	}
}

func fullBackendKernelPlan(revision, rootRole string, denied, audited int, container string) sandboxpolicy.Plan {
	yes := true
	actor := func(role string) *api.Actor {
		return &api.Actor{Path: []string{"/probe/init", "/probe/role"}, FromImage: &yes, Ancestor: &api.Ancestor{Path: []string{"/probe/init", "/probe/role"}, Depth: 2}, Role: []string{role}, UID: []int64{0}, Container: []string{container}}
	}
	target := func(paths []string) api.ExecTarget {
		return api.ExecTarget{PathTarget: api.PathTarget{Path: paths, FromImage: &yes, FSType: []string{"overlay"}}, Argv: &api.ArgvPredicate{Contains: []string{"--token=ok"}, Prefix: []string{"--token="}, StdinIsPipe: &yes}}
	}
	paths := make([]string, 13)
	for i := range paths {
		paths[i] = fmt.Sprintf("/probe/target-%d", i)
	}
	stage := target([]string{"/probe/role"})
	stage.SetRole = "worker"
	return sandboxpolicy.Plan{Revision: revision, Policies: []sandboxpolicy.CompiledPolicy{{Identity: sandboxpolicy.PolicyIdentity{Kind: "SandboxPolicy", Name: "fixture", UID: "fixture-policy-uid"}, Revision: "policy-" + revision, Mode: "enforce", RootRole: rootRole, Exec: api.ExecSection{Default: api.ActionDeny, Rules: []api.ExecRule{
		{Rule: api.Rule{Name: "root-paths", Origin: "fixture/full-predicates", Action: api.ActionAllow, Actor: actor("agent")}, Target: target(paths)},
		{Rule: api.Rule{Name: "deny-control", Action: api.ActionDeny}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{fmt.Sprintf("/probe/target-%d", denied)}}}},
		{Rule: api.Rule{Name: "audit-control", Action: api.ActionDeny, Mode: api.RuleAudit}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{fmt.Sprintf("/probe/target-%d", audited)}}}},
		{Rule: api.Rule{Name: "root-role-control", Action: api.ActionDeny, Actor: &api.Actor{Role: []string{"agent"}}}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/probe/target-12"}}}},
		{Rule: api.Rule{Name: "grant-worker", Action: api.ActionAllow, Actor: actor("agent")}, Target: stage},
		{Rule: api.Rule{Name: "inherited-worker", Action: api.ActionAllow, Actor: actor("worker")}, Target: target([]string{"/probe/target-12"})},
	}}}}}
}

func fullBackendKernelImage(t *testing.T) (oras.ReadOnlyTarget, string) {
	t.Helper()
	if archive := os.Getenv("IG_FULL_BACKEND_ARCHIVE"); archive != "" {
		store, err := orasoci.NewFromTar(context.Background(), archive)
		require.NoError(t, err)
		return store, "localhost/enforce-exec-owner:trusted-combined-fixture"
	}
	ctx := context.Background()
	store := memory.New()
	read := func(env string) []byte {
		path := os.Getenv(env)
		require.NotEmpty(t, path)
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		return b
	}
	push := func(media string, b []byte) ocispec.Descriptor {
		d := content.NewDescriptorFromBytes(media, b)
		require.NoError(t, store.Push(ctx, d, bytes.NewReader(b)))
		return d
	}
	cfg := push("application/vnd.gadget.config.v1+yaml", read("IG_FULL_BACKEND_METADATA"))
	layer := push("application/vnd.gadget.ebpf.program.v1+binary", read("IG_FULL_BACKEND_OBJECT"))
	raw, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: []ocispec.Descriptor{layer}})
	require.NoError(t, err)
	manifest := push(ocispec.MediaTypeImageManifest, raw)
	manifest.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
	raw, err = json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{manifest}})
	require.NoError(t, err)
	desc := push(ocispec.MediaTypeImageIndex, raw)
	const image = "localhost/enforce-exec-owner:trusted-combined-fixture"
	require.NoError(t, store.Tag(ctx, desc, image))
	return store, image
}

type fullBackendControl struct {
	request, response int
	buffer            []byte
}

func openFullBackendControl(ctx context.Context, pid uint32) (*fullBackendControl, error) {
	root := fmt.Sprintf("/proc/%d/root/fixture-control", pid)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request, err := unix.Open(filepath.Join(root, "request"), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENXIO) {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			return nil, err
		}
		response, err := unix.Open(filepath.Join(root, "response"), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(request)
			return nil, err
		}
		for _, fd := range []int{request, response} {
			var stat unix.Stat_t
			if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO {
				unix.Close(request)
				unix.Close(response)
				return nil, fmt.Errorf("fixture control is not FIFO: %w", err)
			}
		}
		return &fullBackendControl{request: request, response: response}, nil
	}
}
func (c *fullBackendControl) close() { unix.Close(c.request); unix.Close(c.response) }
func (c *fullBackendControl) command(ctx context.Context, command string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	bytes := []byte(command + "\n")
	n, err := unix.Write(c.request, bytes)
	if err != nil {
		return 0, err
	}
	if n != len(bytes) {
		return 0, fmt.Errorf("short fixture command write")
	}
	for {
		if index := bytesIndexNewline(c.buffer); index >= 0 {
			line := string(c.buffer[:index])
			c.buffer = c.buffer[index+1:]
			value, ok := strings.CutPrefix(line, "RESULT ")
			if !ok {
				return 0, fmt.Errorf("unexpected fixture reply %q", line)
			}
			return strconv.Atoi(value)
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		fds := []unix.PollFd{{Fd: int32(c.response), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 20)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var buf [128]byte
		n, err := unix.Read(c.response, buf[:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, fmt.Errorf("fixture response closed")
		}
		c.buffer = append(c.buffer, buf[:n]...)
		if len(c.buffer) > 1024 {
			return 0, fmt.Errorf("oversized fixture response")
		}
	}
}
func bytesIndexNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}

func TestFullBackendKernelFixturePlan(t *testing.T) {
	for _, revision := range []string{"plan-1", "plan-2"} {
		p := fullBackendKernelPlan(revision, "agent", 0, 1, "app")
		program, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, p, 1, nil)
		require.NoError(t, err)
		rule, err := fullpolicy.Decode[fullpolicy.KernelRule](program.Entries[fullpolicy.KernelRuleBase])
		require.NoError(t, err)
		require.Equal(t, uint32(13), rule.TargetPath.Count)
	}
}

func proveFullBackendDeviceBarrier(t *testing.T, ctx context.Context, control *fullBackendControl, pid uint32) {
	t.Helper()
	registered, err := os.ReadFile("/proc/devices")
	require.NoError(t, err)
	used := map[uint32]bool{}
	for _, line := range strings.Split(string(registered), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 32)
		if err == nil {
			used[uint32(n)] = true
		}
	}
	var major uint32
	for n := uint32(511); n >= 240; n-- {
		if !used[n] {
			major = n
			break
		}
	}
	require.NotZero(t, major, "need an unregistered fixture device major")
	for _, kind := range []struct {
		name, sys string
		mode      uint32
	}{{"char", "char", unix.S_IFCHR}, {"block", "block", unix.S_IFBLK}} {
		device := fmt.Sprintf("%d:0", major)
		_, err := os.Stat(filepath.Join("/sys/dev", kind.sys, device))
		require.True(t, os.IsNotExist(err), "device must not be registered")
		name := fmt.Sprintf("/proc/%d/root/dev/shm/sandbox-policy-device-%s", pid, kind.name)
		_, err = os.Lstat(name)
		require.True(t, os.IsNotExist(err), "never replace a preexisting shm file")
		require.NoError(t, unix.Mknod(name, kind.mode|0666, int(unix.Mkdev(major, 0))))
		func() {
			defer func() { require.NoError(t, os.Remove(name)) }()
			require.NoError(t, os.Chmod(name, 0666))
			code, err := control.command(ctx, "DEVICE "+kind.name)
			require.NoError(t, err)
			require.Equal(t, 77, code, "actual bound init must receive EPERM before opening unknown %s device", kind.name)
		}()
	}
	t.Logf("actual bound init rejected unregistered char/block major %d opens with EPERM", major)
}
