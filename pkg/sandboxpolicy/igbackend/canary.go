package igbackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// The section canary proves that the BPF LSM hooks of a section run on this
// kernel. An attached link is not a hook that runs: bpf missing from the
// boot lsm= list, ftrace off, or a hook whose call is never switched on all
// keep the link and silently skip the program. The canary is the exec
// engine's attach canary (fullruntime.RunAttachCanary): with BPF run
// statistics on, a child process makes harmless calls that pass through each
// hook (canaryTriggers), and the run count of every program must rise.
//
// It runs right after each start of a section instance (in the background,
// so it does not delay the start) and then every canaryInterval while the
// instance runs. Until the first result, the section is not Ready
// (<Section>CanaryUnavailable, "not run yet"). A silent hook is latched until
// node-agent restarts (tasks ran unprotected in the window). A canary that
// cannot run (run statistics, the child, a missing receipt) is unknown, not
// silent; canaryAttempts unknown results in a row are latched too. The
// result is read by CheckSectionKernelRuntime's caller at every status write:
// the section's policies are then not Ready, with the reason
// <Section>HooksSilent or <Section>CanaryUnavailable. Hooks the canary does
// not prove (HooksUnproven) leave the section Ready and are named in its
// policies' status.

// canaryArg, as the first argument of this binary, runs the canary child
// (canary_child_linux.go): the next arguments are the hooks to pass through
// and the directory the child works in and writes its call results to
// (canaryResults). The parent makes and removes that directory.
const canaryArg = "__sandbox-section-canary"

const (
	// canaryInterval is the period of the live canary.
	canaryInterval = 5 * time.Minute
	// canaryRetry is the first wait after an unknown result; it doubles
	// with each unknown result in a row, up to canaryInterval.
	canaryRetry = 30 * time.Second
	// canaryAttempts unknown results in a row are latched.
	canaryAttempts = 3
)

// canaryNeverProvable: hooks with no harmless trigger on any node (they load
// kernel code). They are named in the Ready message of the section's
// policies; a hook not proven for a cause of this node is a Degraded
// condition (sandboxpolicy.HooksUnproven).
var canaryNeverProvable = map[string]bool{"kernel_read_file": true, "kernel_load_data": true, "kernel_module_request": true}

// runAttachCanary is the exec engine's attach canary; tests replace it.
var runAttachCanary = fullruntime.RunAttachCanary

type sectionCanary struct {
	section  string
	programs map[string]string // program name -> hook
	run      func(context.Context, map[string]*operators.NativeAttachment, []string) error
	// unprovable returns why a hook has no harmless trigger here, or "".
	unprovable      func(hook string) string
	interval, retry time.Duration

	mu        sync.Mutex
	latched   error // sticky until node-agent restarts
	unknown   error // the last unknown result, not yet latched
	failures  int   // unknown results in a row
	recorded  bool  // a check has recorded a result
	started   bool  // an instance has started its live canary (watch)
	notProven map[string]string
}

func newSectionCanary(section string, programs map[string]string) *sectionCanary {
	return &sectionCanary{section: section, programs: programs, run: runAttachCanary, unprovable: canaryUnprovable,
		interval: canaryInterval, retry: canaryRetry}
}

func (c *sectionCanary) title() string {
	return strings.ToUpper(c.section[:1]) + c.section[1:]
}

// Err returns why the section's hooks are not proven to run, or nil. After
// an instance started and before the first result it is
// <Section>CanaryUnavailable: nothing proves the hooks yet. Before any
// instance started it is nil: nothing of the section runs, and the policy's
// status names why (for example a plan that did not translate).
func (c *sectionCanary) Err() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latched != nil {
		return c.latched
	}
	if c.started && !c.recorded {
		return &sandboxpolicy.EnforcementUnavailableError{Section: c.section, Reason: c.title() + "CanaryUnavailable",
			Detail: "the hook canary has not run yet since the section started; the section's hooks are not proven to run"}
	}
	return c.unknown
}

// HooksUnproven returns the hooks the last result did not prove: the ones no
// node can prove (Always), and the ones not proven on this node (Node).
func (c *sectionCanary) HooksUnproven() sandboxpolicy.HooksUnproven {
	var out sandboxpolicy.HooksUnproven
	if c == nil {
		return out
	}
	for hook, why := range c.NotProven() {
		m := &out.Node
		if canaryNeverProvable[hook] {
			m = &out.Always
		}
		if *m == nil {
			*m = map[string]string{}
		}
		(*m)[hook] = why
	}
	return out
}

// NotProven returns the hooks the last result does not cover, with the
// reason.
func (c *sectionCanary) NotProven() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.notProven))
	for h, r := range c.notProven {
		out[h] = r
	}
	return out
}

// check runs the canary once over the receipts that lookup returns (by
// program name) and records the result.
func (c *sectionCanary) check(ctx context.Context, lookup func(name string) *operators.NativeAttachment) {
	receipts := map[string]*operators.NativeAttachment{}
	hooks := map[string]bool{}
	notProven := map[string]string{}
	var missing []string
	for name, hook := range c.programs {
		if why := c.unprovable(hook); why != "" {
			notProven[hook] = why
			continue
		}
		r := lookup(name)
		if r == nil {
			missing = append(missing, name+" ("+hook+")")
			continue
		}
		receipts[name] = r
		hooks[hook] = true
	}
	var err error
	if len(missing) > 0 {
		sort.Strings(missing)
		err = fmt.Errorf("no live link to test: %s", strings.Join(missing, ", "))
	} else {
		err = c.runChild(ctx, receipts, hooks, notProven)
	}
	if ctx.Err() != nil {
		return // stopped: the result says nothing about the hooks
	}
	c.record(err, notProven)
}

// runChild runs the canary over receipts in a temporary directory. A silent
// program whose hook's own call may have been refused before the hook
// (canaryResults: seccomp, a missing capability or another LSM in
// node-agent's container, a quota, or a file the call needed) says nothing
// about the hook: it moves to notProven. Any other silent
// program stays silent.
func (c *sectionCanary) runChild(ctx context.Context, receipts map[string]*operators.NativeAttachment, hooks map[string]bool, notProven map[string]string) error {
	dir, err := os.MkdirTemp("", "kubescape-sandbox-canary-")
	if err != nil {
		return fmt.Errorf("canary directory: %w", err)
	}
	defer os.RemoveAll(dir)
	list := make([]string, 0, len(hooks))
	for h := range hooks {
		list = append(list, h)
	}
	sort.Strings(list)
	err = c.run(ctx, receipts, []string{"/proc/self/exe", canaryArg, strings.Join(list, ","), dir})
	var silent *fullruntime.AttachCanarySilentError
	if !errors.As(err, &silent) {
		return err
	}
	refused := canaryResults(dir)
	var still []string
	for _, name := range silent.Programs {
		hook := c.programs[name]
		if why, ok := refused[hook]; ok {
			notProven[hook] = "its call was refused (" + why + "), maybe before the hook could run: seccomp, a missing capability, another LSM, a quota or a missing fixture can stop it for node-agent"
			continue
		}
		still = append(still, name+" ("+hook+")")
	}
	if len(still) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s did not run while the canary passed through it", fullruntime.ErrAttachCanarySilent, strings.Join(still, ", "))
}

func (c *sectionCanary) record(err error, notProven map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notProven, c.recorded = notProven, true
	switch {
	case c.latched != nil:
	case err == nil:
		c.unknown, c.failures = nil, 0
	case errors.Is(err, fullruntime.ErrAttachCanarySilent):
		c.latched = &sandboxpolicy.EnforcementUnavailableError{Section: c.section, Reason: c.title() + "HooksSilent",
			Detail: fmt.Sprintf("a BPF LSM hook of the section is attached but does not run on this kernel (%v); latched until node-agent restarts", err)}
	default:
		c.failures++
		c.unknown = &sandboxpolicy.EnforcementUnavailableError{Section: c.section, Reason: c.title() + "CanaryUnavailable",
			Detail: fmt.Sprintf("the hook canary could not run (%v); the section's hooks are not proven to run", err)}
		if c.failures >= canaryAttempts {
			c.latched = c.unknown
		}
	}
	if c.latched != nil {
		logger.L().Warning("sandbox section canary failed", helpers.String("section", c.section), helpers.Error(c.latched))
	} else if c.unknown != nil {
		logger.L().Warning("sandbox section canary could not run", helpers.String("section", c.section),
			helpers.Int("attempt", c.failures), helpers.Error(c.unknown))
	}
	if len(notProven) > 0 {
		logger.L().Info("sandbox section canary: hooks not proven to run", helpers.String("section", c.section),
			helpers.String("hooks", fmt.Sprint(notProven)))
	}
}

// nextWait is the wait before the next live check: retry while no result is
// recorded yet (a first check stopped before its result), doubled per
// unknown result in a row, else interval.
func (c *sectionCanary) nextWait() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.latched != nil:
		return c.interval
	case !c.recorded:
		return c.retry
	case c.unknown != nil:
		wait := c.retry << (c.failures - 1)
		if wait <= 0 || wait > c.interval {
			wait = c.interval
		}
		return wait
	}
	return c.interval
}

// watch runs check at once, then every interval (retry after an unknown
// result), until the returned stop is called; stop waits for a running
// check.
func (c *sectionCanary) watch(lookup func(name string) *operators.NativeAttachment) (stop func()) {
	if c == nil {
		return func() {}
	}
	c.mu.Lock()
	c.started = true
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wait time.Duration // the instance's first check: at once
		for {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			c.mu.Lock()
			latched := c.latched != nil
			c.mu.Unlock()
			if !latched { // nothing clears a latch; keep the goroutine cheap
				c.check(ctx, lookup)
			}
			wait = c.nextWait()
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done }) }
}

// gcReceipts looks up a running instance's attach receipts by program name.
func gcReceipts(gc operators.GadgetContext) func(string) *operators.NativeAttachment {
	return func(name string) *operators.NativeAttachment {
		if gc == nil {
			return nil
		}
		value, _ := gc.GetVar(operators.NativeAttachmentPrefix + name)
		r, _ := value.(*operators.NativeAttachment)
		return r
	}
}
