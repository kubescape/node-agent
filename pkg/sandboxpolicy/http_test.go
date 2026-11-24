package sandboxpolicy

import (
	"context"
	"reflect"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

func httpSection(onUnavailable api.HTTPUnavailable) *api.HTTPSection {
	return &api.HTTPSection{
		Default:       api.HTTPDefault{LLM: api.HTTPDefaultAudit, MCP: api.HTTPDefaultAudit, Other: api.HTTPDefaultAllow},
		OnUnavailable: onUnavailable,
		Decrypt:       &api.HTTPDecrypt{ExactHosts: []string{"api.example.com"}},
	}
}

// The http block of the node status comes from Options.HTTPStatus, for
// policies with an http section only, and only when the node runs the gateway
// redirect.
func TestStatusHTTPBlock(t *testing.T) {
	ctx := context.Background()
	with := policy("with-http", "ns")
	with.Spec.HTTP = httpSection("")
	without := policy("without-http", "ns")
	c, _, w, _ := setup(t, with, without)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.reports["with-http"].Status.HTTP; got != nil {
		t.Fatalf("no gateway redirect on this node, yet an http block was written: %+v", got)
	}

	var asked []types.UID
	want := api.HTTPNodeStatus{BoundPods: 2, PreAttachBypass: 1, NeedRestart: []string{"ns/pod-a"}, Gate: api.HTTPGateFailingOpen, NodeControllerDegraded: true}
	// The hook is set, but the redirect is not running: still no block.
	running := false
	c.options.HTTPStatus = func(uid types.UID) (*api.HTTPNodeStatus, bool) {
		asked = append(asked, uid)
		if !running {
			return nil, false
		}
		block := want
		return &block, true
	}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.reports["with-http"].Status; got.HTTP != nil || got.Truncated {
		t.Fatalf("the redirect is not running, yet an http block was written: %+v", got.HTTP)
	}
	running = true
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	report := w.reports["with-http"].Status
	if report.HTTP == nil || !reflect.DeepEqual(*report.HTTP, want) || !report.Truncated {
		t.Errorf("http block %+v truncated %v, want %+v and truncated", report.HTTP, report.Truncated, want)
	}
	if got := w.reports["without-http"].Status; got.HTTP != nil || got.Truncated {
		t.Errorf("a policy without an http section got an http block: %+v", got.HTTP)
	}
	for _, uid := range asked {
		if uid != "with-http" {
			t.Errorf("HTTPStatus was asked about %q", uid)
		}
	}
	if len(asked) == 0 {
		t.Error("HTTPStatus was never asked")
	}
}

func TestHTTPPolicies(t *testing.T) {
	ctx := context.Background()
	allow := policy("b-allow", "ns")
	allow.Spec.HTTP = httpSection(api.HTTPUnavailableAllow)
	deny := policy("a-deny", "ns")
	deny.Spec.HTTP = httpSection(api.HTTPUnavailableDeny)
	off := policy("c-off", "ns")
	off.Spec.HTTP = httpSection("")
	off.Spec.Mode = api.ModeOff
	other := policy("d-other-namespace", "elsewhere")
	other.Spec.HTTP = httpSection("")
	plain := policy("e-no-http", "ns")
	broken := policy("f-broken", "ns")
	broken.Spec.HTTP = httpSection("")
	broken.Spec.Containers = nil
	c, _, _, _ := setup(t, allow, deny, off, other, plain, broken)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	_ = c.InitialSync(ctx) // the broken policy makes it return an error

	got := c.HTTPPolicies()
	type row struct {
		uid       types.UID
		off, deny bool
		selects   bool
	}
	var rows []row
	for _, p := range got {
		rows = append(rows, row{p.Identity.UID, p.Off, p.Deny, p.Selects(binding())})
	}
	want := []row{
		{"a-deny", false, true, true},
		{"b-allow", false, false, true},
		{"c-off", true, false, true},
		{"d-other-namespace", false, false, false},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("got %+v\nwant %+v", rows, want)
	}
	if got[0].Identity.Generation != 1 || got[0].Identity.Kind != "SandboxPolicy" {
		t.Errorf("identity %+v", got[0].Identity)
	}
}
