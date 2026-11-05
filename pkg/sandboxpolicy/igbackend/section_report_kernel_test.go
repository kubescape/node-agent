//go:build linux && sandboxpolicy_kernel

package igbackend

// Opt-in kernel test of the section verdict export with the real gadget
// images: for each of privilege, network and file, one enforced deny and one
// audit wouldDeny reach a receiver with their binding, policy and target.
// Requires root, BPF LSM and a disposable Docker container (busybox applets
// unshare, nc and cat) started with seccomp=unconfined, apparmor=unconfined
// and --cap-add SYS_ADMIN:
//
//	IG_SECTION_KERNEL_TEST=1
//	IG_SECTION_IMAGE_ARCHIVE  OCI archive from `ig image export` with the three images
//	IG_PRIVILEGE_IMAGE, IG_NETWORK_IMAGE, IG_FILE_IMAGE  image names in the archive
//	IG_SECTION_CONTAINER_ID   full Docker container ID
//	IG_SECTION_CGROUP_PATH    its cgroup v2 path, with a leading "/"

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	orasoci "oras.land/oras-go/v2/content/oci"
)

type sectionKernelReceiver struct{ events chan utils.K8sEvent }

func (r *sectionKernelReceiver) ReportEvent(_ utils.EventType, e utils.K8sEvent) {
	select {
	case r.events <- e:
	default:
	}
}

type sectionKernelBackend interface {
	sandboxpolicy.Backend
	SlotPolicies(uint64, uint32) ([]sandboxpolicy.CompiledPolicy, bool)
	VerdictStats() VerdictStats
	Close(context.Context) error
}

func TestSectionVerdictExportKernel(t *testing.T) {
	if os.Getenv("IG_SECTION_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	if err := CheckBPFLSM("/"); err != nil {
		t.Fatalf("this test needs an active BPF LSM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	id, cgroupPath := os.Getenv("IG_SECTION_CONTAINER_ID"), os.Getenv("IG_SECTION_CGROUP_PATH")
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	binding := sandboxpolicy.Binding{Runtime: "docker", ContainerID: id, CgroupID: st.Ino, CgroupPath: cgroupPath, Namespace: "ns", PodName: "pod", ContainerName: "app"}
	store, err := orasoci.NewFromTar(ctx, os.Getenv("IG_SECTION_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err = rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	run := func(args ...string) error {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return exec.CommandContext(c, "docker", append([]string{"exec", id}, args...)...).Run()
	}
	identity := func(name string) sandboxpolicy.PolicyIdentity {
		return sandboxpolicy.PolicyIdentity{Kind: "SandboxPolicy", Namespace: "ns", Name: name, UID: types.UID("uid-" + name), Generation: 4}
	}
	mode := func(audit bool) (api.PolicyMode, string) {
		if audit {
			return api.ModeAudit, "audit"
		}
		return api.ModeEnforce, "enforce"
	}

	for _, c := range []struct {
		section string
		key     utils.EventType
		backend func(SectionReporter) (sectionKernelBackend, error)
		policy  func(audit bool) sandboxpolicy.CompiledPolicy
		trigger func() error
		check   func(t *testing.T, e utils.K8sEvent)
	}{
		{
			section: sandboxpolicy.SectionPrivilege, key: utils.PrivilegeAuthorizationEventType,
			backend: func(r SectionReporter) (sectionKernelBackend, error) {
				e, err := NewNativePrivilegeEngine(rt, simple.New("no-kubernetes"), store, os.Getenv("IG_PRIVILEGE_IMAGE"), r)
				if err != nil {
					return nil, err
				}
				return NewPrivilege(e, nil, "export-test")
			},
			policy: func(audit bool) sandboxpolicy.CompiledPolicy {
				m, _ := mode(audit)
				return sandboxpolicy.CompiledPolicy{Identity: identity("priv"), Revision: string(m), Mode: m, Privilege: &api.PrivilegeSection{Default: api.ActionAllow,
					Rules: []api.PrivilegeRule{{Rule: api.Rule{Name: "no-mount-ns", Action: api.ActionDeny, Origin: "custom/priv/no-mount-ns"},
						Target: api.PrivilegeTarget{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}}}}
			},
			trigger: func() error { return run("unshare", "-m", "true") },
			check: func(t *testing.T, e utils.K8sEvent) {
				p := e.(*sandboxpolicy.PrivilegeVerdictEvent)
				if p.Target.Syscall != "unshare" || p.Target.Hook == "" {
					t.Errorf("privilege target %+v", p.Target)
				}
				t.Logf("privilege target %+v", p.Target)
			},
		},
		{
			section: sandboxpolicy.SectionNetwork, key: utils.NetworkAuthorizationEventType,
			backend: func(r SectionReporter) (sectionKernelBackend, error) {
				e, err := NewNativeNetworkEngine(rt, simple.New("no-kubernetes"), store, os.Getenv("IG_NETWORK_IMAGE"), NetworkTierLSM, r)
				if err != nil {
					return nil, err
				}
				return NewNetwork(e, nil, "export-test")
			},
			policy: func(audit bool) sandboxpolicy.CompiledPolicy {
				m, s := mode(audit)
				doc := netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: s, Egress: netpolicy.Section{Default: "allow",
					Rules: []netpolicy.Rule{{Name: "no-test-net", Action: "deny", Origin: "custom/net/no-test-net", CIDRs: []string{"192.0.2.0/24"}}}}}}
				return sandboxpolicy.CompiledPolicy{Identity: identity("net"), Revision: s, Mode: m, Network: &sandboxpolicy.NetworkPlan{Egress: doc}}
			},
			// Audit lets the connect start; nothing answers on 192.0.2.1.
			trigger: func() error { return run("nc", "-w", "1", "192.0.2.1", "80") },
			check: func(t *testing.T, e utils.K8sEvent) {
				n := e.(*sandboxpolicy.NetworkVerdictEvent)
				if n.Target.Addr != "192.0.2.1" || n.Target.Port != 80 || n.Target.Version != 4 || n.Target.Proto == "" || n.Target.Hook == "" {
					t.Errorf("network target %+v", n.Target)
				}
				t.Logf("network target %+v", n.Target)
			},
		},
		{
			section: sandboxpolicy.SectionFile, key: utils.FileAuthorizationEventType,
			backend: func(r SectionReporter) (sectionKernelBackend, error) {
				e, err := NewNativeFileEngine(rt, simple.New("no-kubernetes"), store, os.Getenv("IG_FILE_IMAGE"), r)
				if err != nil {
					return nil, err
				}
				return NewFile(e, nil, "export-test")
			},
			policy: func(audit bool) sandboxpolicy.CompiledPolicy {
				m, s := mode(audit)
				defaults := map[string]filepolicy.Default{}
				for _, k := range filepolicy.AccessKinds {
					defaults[k] = filepolicy.Default{Action: "allow"}
				}
				doc := filepolicy.Document{Version: 1, Policy: filepolicy.Policy{Mode: s, File: filepolicy.Section{Defaults: defaults,
					Rules: []filepolicy.Rule{{Name: "no-hostname", Action: "deny", Origin: "custom/file/no-hostname", Access: []string{filepolicy.AccessRead}, Paths: []string{"/etc/hostname"}}}}}}
				return sandboxpolicy.CompiledPolicy{Identity: identity("file"), Revision: s, Mode: m, File: &sandboxpolicy.FilePlan{Doc: doc}}
			},
			trigger: func() error { return run("cat", "/etc/hostname") },
			check: func(t *testing.T, e utils.K8sEvent) {
				f := e.(*sandboxpolicy.FileVerdictEvent)
				if f.Target.Access != filepolicy.AccessRead || f.Target.Path != "/etc/hostname" || f.Target.Hook != "file_open" {
					t.Errorf("file target %+v", f.Target)
				}
				t.Logf("file target %+v", f.Target)
			},
		},
	} {
		t.Run(c.section, func(t *testing.T) {
			receiver := &sectionKernelReceiver{events: make(chan utils.K8sEvent, 64)}
			receivers := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
			receivers.Set(c.key, mapset.NewSet[containerwatcher.GenericEventReceiver](receiver))
			var backend sectionKernelBackend
			exporter, err := sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 64, Receivers: receivers,
				ResolveCgroup: func(cgroup uint64) (sandboxpolicy.Binding, bool) { return binding, cgroup == binding.CgroupID },
				SlotPolicies: func(_ string, generation uint64, slot uint32) ([]sandboxpolicy.CompiledPolicy, bool) {
					return backend.SlotPolicies(generation, slot)
				}})
			if err != nil {
				t.Fatal(err)
			}
			runCtx, stop := context.WithCancel(ctx)
			defer stop()
			go func() { _ = exporter.Run(runCtx) }()
			backend, err = c.backend(func(e sandboxpolicy.SectionEvent) { _ = exporter.ReportSection(runCtx, e) })
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close(context.Background())
			if err := c.trigger(); err != nil && c.section != sandboxpolicy.SectionNetwork {
				t.Fatalf("baseline %s call failed: %v", c.section, err)
			}
			for _, audit := range []bool{false, true} {
				policy := c.policy(audit)
				if r, err := backend.Replace(ctx, binding, sandboxpolicy.Plan{Revision: policy.Revision, Policies: []sandboxpolicy.CompiledPolicy{policy}}); err != nil || !r.Committed {
					t.Fatalf("audit=%v plan: %+v %v", audit, r, err)
				}
				err := c.trigger()
				if !audit && err == nil {
					t.Fatalf("%s call allowed under the enforce plan", c.section)
				}
				if audit && err != nil && c.section != sandboxpolicy.SectionNetwork {
					t.Fatalf("%s call denied under the audit plan: %v", c.section, err)
				}
				var got sandboxpolicy.SectionEvent
				deadline := time.After(10 * time.Second)
				for got == nil {
					select {
					case e := <-receiver.events:
						if s, ok := e.(sandboxpolicy.SectionEvent); ok && e.(interface{ GetPID() uint32 }).GetPID() != 0 {
							v := sectionVerdictOf(s)
							if v.WouldDeny == audit {
								got = s
							}
						}
					case <-deadline:
						t.Fatalf("audit=%v: no %s verdict exported; exporter %+v kernel %+v", audit, c.section, exporter.Stats(), backend.VerdictStats())
					}
				}
				v := sectionVerdictOf(got)
				wantMode := api.RuleEnforce
				if audit {
					wantMode = api.RuleAudit
				}
				if got.GetEventType() != c.key || v.Verdict != api.ActionDeny || v.Mode != wantMode || v.Reason != "matching_rule" {
					t.Errorf("audit=%v verdict %+v", audit, v)
				}
				if v.Policy != policy.Identity || len(v.PolicySet) != 1 || v.PolicySet[0].Revision != policy.Revision || len(v.Matches) != 1 || !v.MatchesComplete {
					t.Errorf("audit=%v attribution %+v", audit, v)
				}
				if len(v.Origins) != 1 || v.Origins[0] == "" || v.Matches[0].Origin != v.Origins[0] {
					t.Errorf("audit=%v origins %v matches %+v", audit, v.Origins, v.Matches)
				}
				if got.GetContainerID() != id || got.GetPod() != "pod" || v.CgroupID != binding.CgroupID || v.Comm == "" {
					t.Errorf("audit=%v actor/binding: container %q comm %q cgroup %d", audit, got.GetContainerID(), v.Comm, v.CgroupID)
				}
				c.check(t, got)
				t.Logf("audit=%v rule=%s origins=%v generation=%d slot=%d pid=%d comm=%s", audit, v.Rule, v.Origins, v.Generation, v.Slot, v.PID, v.Comm)
			}
			stats := backend.VerdictStats()
			if total := stats.Live.Denied + stats.Retired.Denied; total < 2 || stats.Live.Submitted+stats.Retired.Submitted < 2 {
				t.Errorf("kernel counters %+v", stats)
			}
			t.Logf("kernel counters %+v exporter %+v", stats, exporter.Stats())
			if r, err := backend.Withdraw(ctx, binding); err != nil || !r.Committed {
				t.Fatalf("withdraw: %+v %v", r, err)
			}
		})
	}
}

func sectionVerdictOf(e sandboxpolicy.SectionEvent) sandboxpolicy.SectionVerdict {
	switch v := e.(type) {
	case *sandboxpolicy.PrivilegeVerdictEvent:
		return v.Verdict
	case *sandboxpolicy.NetworkVerdictEvent:
		return v.Verdict
	case *sandboxpolicy.FileVerdictEvent:
		return v.Verdict
	}
	return sandboxpolicy.SectionVerdict{}
}
