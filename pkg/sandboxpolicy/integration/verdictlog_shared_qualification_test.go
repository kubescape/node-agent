//go:build sandbox_shared_qualification

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func verdictLogSample() (sandboxpolicy.Verdict, sandboxpolicy.Binding) {
	epoch, cookie, exec, pass := uint64(0x5eed), uint64(77), uint64(3), uint32(1)
	image := true
	policy := sandboxpolicy.PolicyIdentity{Kind: "SandboxPolicy", Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 3}
	v := sandboxpolicy.Verdict{
		Time: time.Unix(1710000000, 0), Policy: policy, PolicySet: []sandboxpolicy.PolicyRevision{{Policy: policy, Revision: "p1"}}, Revision: "rev", Rule: "audit-deny",
		Mode: api.RuleAudit, Verdict: api.ActionDeny, WouldDeny: true, Reason: "matching_rule", MatchesComplete: true,
		ContainerID: "container", PodUID: "pod-uid", BindingPID: 20, MountNamespace: 21, CgroupID: 19, PID: 41,
		TargetPath: "/bin/target", Argv: []string{"target", "--password=hunter2"}, FromImage: &image, LoadEpoch: &epoch, TaskCookie: &cookie, ExecID: &exec, Pass: &pass,
	}
	b := sandboxpolicy.Binding{ContainerID: "container", CgroupID: 19, PodUID: "pod-uid", PID: 20, MountNamespace: 21, Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}
	return v, b
}

func TestVerdictLogReceiverWritesOneJSONLine(t *testing.T) {
	out := &lockedBuffer{}
	r := &verdictLogReceiver{out: out}
	v, b := verdictLogSample()
	r.ReportEvent(utils.ExecAuthorizationEventType, sandboxpolicy.NewExecVerdictEvent(v, b))
	got := out.String()
	if !strings.HasPrefix(got, VerdictLogPrefix) || !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("line %q", got)
	}
	for _, want := range []string{`"wouldDeny":true`, `"deny":true`, `"mode":"audit"`, `"reason":"matching_rule"`, `"loadEpoch":24301`, `"taskCookie":77`, `"execId":3`, `"targetPath":"/bin/target"`, `"fromImage":true`, `"argvCount":2`, `"pod":"pod"`, `"namespace":"ns"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("line lacks %s: %q", want, got)
		}
	}
	if strings.Contains(got, "hunter2") || strings.Contains(got, `"argv"`) || strings.Contains(got, `"truncated"`) {
		t.Fatalf("argv logged or spurious truncation: %q", got)
	}
	if r.Failures() != 0 {
		t.Fatalf("failures %d", r.Failures())
	}
	var line verdictLogLine
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(got, VerdictLogPrefix), "\n")), &line); err != nil {
		t.Fatal(err)
	}
	if line.ContainerID != "container" || line.PodUID != "pod-uid" || line.Container != "app" || line.Policy.Name != "policy" || line.Rule != "audit-deny" || len(line.PolicySet) != 1 || line.Binding.CgroupID != 19 || line.Binding.PID != 20 || line.Binding.MountNamespace != 21 {
		t.Fatalf("decoded %+v", line)
	}
	// Anything but a verdict event is ignored.
	r.ReportEvent(utils.ExecAuthorizationEventType, nil)
	if out.String() != got {
		t.Fatal("logged a non-verdict event")
	}
}

func TestVerdictLogRegisteredAndReachedByExporter(t *testing.T) {
	receivers := withVerdictLog(nil)
	set, ok := receivers.Load(utils.ExecAuthorizationEventType)
	if !ok || set.Cardinality() != 1 {
		t.Fatal("verdict log receiver not registered")
	}
	// An existing set is extended, never replaced.
	existing := maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	existing.Set(utils.ExecAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver]("other"))
	if set, _ := withVerdictLog(existing).Load(utils.ExecAuthorizationEventType); set.Cardinality() != 2 {
		t.Fatal("existing receivers replaced")
	}
	out := &lockedBuffer{}
	for receiver := range set.Iter() {
		receiver.(*verdictLogReceiver).out = out
	}
	v, b := verdictLogSample()
	exporter, err := sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 1, Receivers: receivers, ResolveBinding: func(sandboxpolicy.Verdict) (sandboxpolicy.Binding, bool) { return b, true }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exporter.Run(ctx) }()
	if err := exporter.ReportVerdict(ctx, v); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for exporter.Stats().Delivered == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("exporter Run: %v", err)
	}
	if s := exporter.Stats(); s.Delivered != 1 || s.Dropped != 0 {
		t.Fatalf("stats %+v", s)
	}
	if got := out.String(); !strings.HasPrefix(got, VerdictLogPrefix) || !strings.Contains(got, `"wouldDeny":true`) || !strings.Contains(got, `"pod":"pod"`) {
		t.Fatalf("line %q", got)
	}
}

func TestVerdictLogLineIsBounded(t *testing.T) {
	v, b := verdictLogSample()
	for i := 0; i < 200; i++ {
		v.PolicySet = append(v.PolicySet, sandboxpolicy.PolicyRevision{Policy: sandboxpolicy.PolicyIdentity{Kind: "SandboxPolicy", Namespace: "ns", Name: fmt.Sprintf("policy-%d", i), UID: "uid"}, Revision: "revision"})
	}
	decode := func(got string) verdictLogLine {
		t.Helper()
		if len(got) > VerdictLogMaxLine || !strings.HasPrefix(got, VerdictLogPrefix) || strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
			t.Fatalf("line of %d bytes: %.200q", len(got), got)
		}
		var line verdictLogLine
		if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(got, VerdictLogPrefix), "\n")), &line); err != nil {
			t.Fatal(err)
		}
		return line
	}
	// A huge PolicySet is dropped first; the paths stay intact.
	out := &lockedBuffer{}
	r := &verdictLogReceiver{out: out}
	r.ReportEvent(utils.ExecAuthorizationEventType, sandboxpolicy.NewExecVerdictEvent(v, b))
	if line := decode(out.String()); !line.Truncated || line.PolicySet != nil || line.TargetPath != "/bin/target" || !line.WouldDeny || line.LoadEpoch == nil {
		t.Fatalf("policySet not dropped %+v", line)
	}
	// Then the longer path is cut, on a rune boundary.
	v.TargetPath = "/" + strings.Repeat("\u00e9", 3000)
	v.ActorPath = "/" + strings.Repeat("a", 1000)
	out = &lockedBuffer{}
	r = &verdictLogReceiver{out: out}
	r.ReportEvent(utils.ExecAuthorizationEventType, sandboxpolicy.NewExecVerdictEvent(v, b))
	line := decode(out.String())
	if !line.Truncated || line.PolicySet != nil || len(line.TargetPath) >= len(v.TargetPath) || !strings.HasPrefix(v.TargetPath, line.TargetPath) || r.Failures() != 0 {
		t.Fatalf("paths not truncated: target %d actor %d failures %d", len(line.TargetPath), len(line.ActorPath), r.Failures())
	}
	// An unshrinkable field cannot fit: nothing is written, the failure counts.
	v.Rule = strings.Repeat("r", VerdictLogMaxLine)
	out = &lockedBuffer{}
	r = &verdictLogReceiver{out: out}
	r.ReportEvent(utils.ExecAuthorizationEventType, sandboxpolicy.NewExecVerdictEvent(v, b))
	if out.String() != "" || r.Failures() != 1 {
		t.Fatalf("oversize line written %d bytes, failures %d", len(out.String()), r.Failures())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestVerdictLogCountsWriteFailures(t *testing.T) {
	r := &verdictLogReceiver{out: failingWriter{}}
	v, b := verdictLogSample()
	r.ReportEvent(utils.ExecAuthorizationEventType, sandboxpolicy.NewExecVerdictEvent(v, b))
	r.ReportEvent(utils.ExecAuthorizationEventType, sandboxpolicy.NewExecVerdictEvent(v, b))
	if r.Failures() != 2 {
		t.Fatalf("failures %d", r.Failures())
	}
}
