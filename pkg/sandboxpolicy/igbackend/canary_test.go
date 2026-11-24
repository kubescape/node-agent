package igbackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// fakeCanaryRun records each canary run and returns the next queued result
// (nil once the queue is empty).
type fakeCanaryRun struct {
	mu       sync.Mutex
	results  []error
	receipts [][]string
	cmds     [][]string
}

func (f *fakeCanaryRun) run(_ context.Context, receipts map[string]*operators.NativeAttachment, cmd []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(receipts))
	for name := range receipts {
		names = append(names, name)
	}
	sort.Strings(names)
	f.receipts = append(f.receipts, names)
	f.cmds = append(f.cmds, cmd)
	if len(f.results) == 0 {
		return nil
	}
	err := f.results[0]
	f.results = f.results[1:]
	return err
}

func (f *fakeCanaryRun) runs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.receipts)
}

var testCanaryPrograms = map[string]string{
	"ig_a_open":   "file_open",
	"ig_a_alloc":  "task_alloc",
	"ig_a_module": "kernel_module_request",
}

func newTestCanary(f *fakeCanaryRun) *sectionCanary {
	c := newSectionCanary(sandboxpolicy.SectionPrivilege, testCanaryPrograms)
	c.run = f.run
	c.unprovable = func(hook string) string {
		if hook == "kernel_module_request" {
			return "no harmless trigger"
		}
		return ""
	}
	return c
}

// allReceipts returns a receipt for every program.
func allReceipts(name string) *operators.NativeAttachment {
	return &operators.NativeAttachment{ProgramID: 1, Target: name}
}

func canaryReason(t *testing.T, err error) string {
	t.Helper()
	var u *sandboxpolicy.EnforcementUnavailableError
	if !errors.As(err, &u) {
		t.Fatalf("not an EnforcementUnavailableError: %v", err)
	}
	if u.Section != sandboxpolicy.SectionPrivilege {
		t.Fatalf("section %q", u.Section)
	}
	return u.Reason
}

func TestSectionCanaryPassRunsProvableHooksOnly(t *testing.T) {
	f := &fakeCanaryRun{}
	c := newTestCanary(f)
	c.check(context.Background(), allReceipts)
	if err := c.Err(); err != nil {
		t.Fatal(err)
	}
	if got, want := f.receipts[0], []string{"ig_a_alloc", "ig_a_open"}; !slices.Equal(got, want) {
		t.Fatalf("receipts %v, want %v", got, want)
	}
	if got, want := f.cmds[0][:3], []string{"/proc/self/exe", canaryArg, "file_open,task_alloc"}; len(f.cmds[0]) != 4 || !slices.Equal(got, want) {
		t.Fatalf("command %v, want %v and a directory", f.cmds[0], want)
	}
	if _, err := os.Stat(f.cmds[0][3]); !os.IsNotExist(err) {
		t.Fatalf("the canary directory was not removed: %v", err)
	}
	if got := c.NotProven(); len(got) != 1 || got["kernel_module_request"] != "no harmless trigger" {
		t.Fatalf("not proven %v", got)
	}
}

func TestSectionCanarySilentLatches(t *testing.T) {
	silent := fmt.Errorf("attach canary: attached but never ran during a fork+exec+exit: ig_a_open (file_open): %w", fullruntime.ErrAttachCanarySilent)
	f := &fakeCanaryRun{results: []error{silent}}
	c := newTestCanary(f)
	c.check(context.Background(), allReceipts)
	err := c.Err()
	if got := canaryReason(t, err); got != "PrivilegeHooksSilent" {
		t.Fatalf("reason %q", got)
	}
	if !strings.Contains(err.Error(), "ig_a_open (file_open)") {
		t.Fatalf("silent hook not named: %v", err)
	}
	// A later pass does not clear it: tasks ran unprotected in the window.
	c.check(context.Background(), allReceipts)
	if got := canaryReason(t, c.Err()); got != "PrivilegeHooksSilent" {
		t.Fatalf("latch cleared: %q", got)
	}
}

func TestSectionCanaryUnavailableRetriesThenLatches(t *testing.T) {
	boom := errors.New("attach canary: exec: boom")
	f := &fakeCanaryRun{results: []error{boom}}
	c := newTestCanary(f)
	c.check(context.Background(), allReceipts)
	if got := canaryReason(t, c.Err()); got != "PrivilegeCanaryUnavailable" {
		t.Fatalf("reason %q", got)
	}
	// One unknown result is not latched: a pass clears it.
	c.check(context.Background(), allReceipts)
	if err := c.Err(); err != nil {
		t.Fatalf("a pass did not clear an unknown result: %v", err)
	}
	// canaryAttempts unknown results in a row latch.
	for i := 0; i < canaryAttempts; i++ {
		f.results = append(f.results, boom)
	}
	for i := 0; i < canaryAttempts; i++ {
		c.check(context.Background(), allReceipts)
	}
	c.check(context.Background(), allReceipts) // a pass
	if got := canaryReason(t, c.Err()); got != "PrivilegeCanaryUnavailable" {
		t.Fatalf("not latched after %d unknown results: %q", canaryAttempts, got)
	}
}

func TestSectionCanaryMissingReceiptIsUnavailable(t *testing.T) {
	f := &fakeCanaryRun{}
	c := newTestCanary(f)
	c.check(context.Background(), func(name string) *operators.NativeAttachment {
		if name == "ig_a_open" {
			return nil
		}
		return allReceipts(name)
	})
	err := c.Err()
	if got := canaryReason(t, err); got != "PrivilegeCanaryUnavailable" {
		t.Fatalf("reason %q", got)
	}
	if !strings.Contains(err.Error(), "file_open") {
		t.Fatalf("hook not named: %v", err)
	}
	if f.runs() != 0 {
		t.Fatal("canary ran without every receipt")
	}
}

func TestSectionCanaryWatchRepeatsAndStops(t *testing.T) {
	f := &fakeCanaryRun{}
	c := newTestCanary(f)
	c.interval, c.retry = 5*time.Millisecond, 5*time.Millisecond
	stop := c.watch(allReceipts)
	deadline := time.Now().Add(5 * time.Second)
	for f.runs() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("the live canary did not repeat")
		}
		time.Sleep(time.Millisecond)
	}
	stop()
	n := f.runs()
	time.Sleep(30 * time.Millisecond)
	if f.runs() != n {
		t.Fatal("the live canary ran after stop")
	}
	stop() // idempotent
}

func TestSectionCanaryNil(t *testing.T) {
	var c *sectionCanary
	if c.Err() != nil {
		t.Fatal("a nil canary has an error")
	}
	c.watch(allReceipts)()
}

type fakeCanaryEngine struct{ err error }

func (f fakeCanaryEngine) CanaryErr() error { return f.err }

// The status-time check reports the kernel runtime first, then the canary;
// a section with no canary engine has no canary result.
func TestSectionKernelRuntimeIncludesCanary(t *testing.T) {
	old := checkKernelRuntime
	t.Cleanup(func() { checkKernelRuntime = old })
	silent := &sandboxpolicy.EnforcementUnavailableError{Section: "file", Reason: "FileHooksSilent"}
	check := SectionKernelRuntime(map[string]CanaryReporter{"file": fakeCanaryEngine{silent}, "network": fakeCanaryEngine{}})

	checkKernelRuntime = func() error { return nil }
	if err := check("file"); !errors.Is(err, silent) {
		t.Fatalf("canary result lost: %v", err)
	}
	if err := check("network"); err != nil {
		t.Fatalf("a passing canary failed: %v", err)
	}
	if err := check("privilege"); err != nil {
		t.Fatalf("no engine: %v", err)
	}
	checkKernelRuntime = func() error {
		return &fullruntime.KernelCheckError{Check: fullruntime.KernelCheckFtrace, Err: errors.New("off")}
	}
	if got := canaryReasonAny(t, check("file")); got != "FtraceDisabled" {
		t.Fatalf("the kernel check does not come first: %q", got)
	}
}

func canaryReasonAny(t *testing.T, err error) string {
	t.Helper()
	var u *sandboxpolicy.EnforcementUnavailableError
	if !errors.As(err, &u) {
		t.Fatalf("not an EnforcementUnavailableError: %v", err)
	}
	return u.Reason
}

// A silent program whose own call was refused before its hook (the child's
// results file) is not proven, not silent; another silent program stays
// silent.
func TestSectionCanaryRefusedTriggerIsNotProven(t *testing.T) {
	for _, tc := range []struct {
		name    string
		silent  []string
		refused string
		reason  string
	}{
		{"only refused", []string{"ig_a_open"}, "file_open EPERM\n", ""},
		{"refused and silent", []string{"ig_a_alloc", "ig_a_open"}, "file_open EPERM\n", "PrivilegeHooksSilent"},
		{"no results file", []string{"ig_a_open"}, "", "PrivilegeHooksSilent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCanary(&fakeCanaryRun{})
			c.run = func(_ context.Context, _ map[string]*operators.NativeAttachment, cmd []string) error {
				if tc.refused != "" {
					if err := os.WriteFile(filepath.Join(cmd[3], canaryResultsFile), []byte(tc.refused), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return &fullruntime.AttachCanarySilentError{Programs: tc.silent}
			}
			c.check(context.Background(), allReceipts)
			err := c.Err()
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("a refused call made the hook silent: %v", err)
				}
				if !strings.Contains(c.NotProven()["file_open"], "EPERM") {
					t.Fatalf("not proven %v", c.NotProven())
				}
				return
			}
			if got := canaryReason(t, err); got != tc.reason {
				t.Fatalf("reason %q", got)
			}
			if strings.Contains(err.Error(), "file_open") && tc.refused != "" {
				t.Fatalf("a refused hook was named silent: %v", err)
			}
		})
	}
}

// A check stopped by its context records nothing: no false failure.
func TestSectionCanaryCancelledRecordsNothing(t *testing.T) {
	c := newTestCanary(&fakeCanaryRun{})
	ctx, cancel := context.WithCancel(context.Background())
	c.run = func(ctx context.Context, _ map[string]*operators.NativeAttachment, _ []string) error {
		cancel()
		return ctx.Err()
	}
	c.check(ctx, allReceipts)
	if err := c.Err(); err != nil {
		t.Fatalf("a cancelled check recorded %v", err)
	}
	if got := c.nextWait(); got != c.retry {
		t.Fatalf("no result yet: next wait %v, want the retry %v", got, c.retry)
	}
}

// Unknown results back off: retry, then doubled, up to the interval.
func TestSectionCanaryBackoff(t *testing.T) {
	f := &fakeCanaryRun{results: []error{errors.New("boom"), errors.New("boom")}}
	c := newTestCanary(f)
	c.retry, c.interval = time.Second, 3*time.Second
	c.check(context.Background(), allReceipts)
	if got := c.nextWait(); got != time.Second {
		t.Fatalf("after one unknown: %v", got)
	}
	c.check(context.Background(), allReceipts)
	if got := c.nextWait(); got != 2*time.Second {
		t.Fatalf("after two unknown: %v", got)
	}
	c.check(context.Background(), allReceipts) // a pass
	if got := c.nextWait(); got != 3*time.Second {
		t.Fatalf("after a pass: %v", got)
	}
}

// An engine without a canary fails closed.
func TestEngineCanaryFailsClosed(t *testing.T) {
	if got := canaryReasonAny(t, EngineCanary("network", struct{}{}).CanaryErr()); got != "NetworkCanaryUnavailable" {
		t.Fatalf("reason %q", got)
	}
	if EngineCanary("network", fakeCanaryEngine{}).CanaryErr() != nil {
		t.Fatal("a real canary engine was replaced")
	}
}
