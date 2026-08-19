package tracers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// fakeRuntime is a minimal runtime.Runtime that fails RunGadget a
// configurable number of times before succeeding, to exercise
// DNSTracer.Start's bounded retry (armosec/private-node-agent#511:
// gadget startup failures in this class are transient/timing-dependent).
type fakeRuntime struct {
	calls     int32
	failCount int32 // number of leading calls that return an error
}

func (f *fakeRuntime) Init(*params.Params) error                              { return nil }
func (f *fakeRuntime) Close() error                                           { return nil }
func (f *fakeRuntime) GlobalParamDescs() params.ParamDescs                    { return nil }
func (f *fakeRuntime) ParamDescs() params.ParamDescs                          { return nil }
func (f *fakeRuntime) SetDefaultValue(params.ValueHint, string)               {}
func (f *fakeRuntime) GetDefaultValue(params.ValueHint) (string, bool)        { return "", false }
func (f *fakeRuntime) IsClient() bool                                         { return false }
func (f *fakeRuntime) GetGadgetInfo(runtime.GadgetContext, *params.Params, api.ParamValues) (*api.GadgetInfo, error) {
	return nil, nil
}

func (f *fakeRuntime) RunGadget(_ runtime.GadgetContext, _ *params.Params, _ api.ParamValues) error {
	n := atomic.AddInt32(&f.calls, 1)
	if n <= f.failCount {
		return errors.New("simulated transient CO-RE/BTF race")
	}
	return nil
}

func TestDNSTracerStartRetriesOnTransientFailure(t *testing.T) {
	fr := &fakeRuntime{failCount: dnsStartMaxRetries - 1} // fail every attempt but the last
	dt := NewDNSTracer(nil, fr, nil, nil, nil, nil)

	require.NoError(t, dt.Start(context.Background()))

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&fr.calls) == int32(dnsStartMaxRetries)
	}, 15*time.Second, 20*time.Millisecond, "expected the tracer to retry until the final attempt succeeds")

	require.NoError(t, dt.Stop())
}

func TestDNSTracerStartGivesUpAfterMaxRetries(t *testing.T) {
	fr := &fakeRuntime{failCount: dnsStartMaxRetries + 10} // always fail
	dt := NewDNSTracer(nil, fr, nil, nil, nil, nil)

	require.NoError(t, dt.Start(context.Background()))

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&fr.calls) == int32(dnsStartMaxRetries)
	}, 15*time.Second, 20*time.Millisecond, "expected the tracer to stop after dnsStartMaxRetries attempts")

	// Give any (incorrect) further retry a chance to happen, then confirm
	// the bound was actually respected.
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, int32(dnsStartMaxRetries), atomic.LoadInt32(&fr.calls))

	require.NoError(t, dt.Stop())
}

func TestDNSTracerStopStopsRetryingMidBackoff(t *testing.T) {
	fr := &fakeRuntime{failCount: dnsStartMaxRetries + 10} // always fail
	dt := NewDNSTracer(nil, fr, nil, nil, nil, nil)

	require.NoError(t, dt.Start(context.Background()))

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&fr.calls) >= 1
	}, 5*time.Second, 10*time.Millisecond, "expected at least one attempt")

	// Stop while an attempt is in flight or the loop is waiting between
	// attempts - not after the context passed to Start was ever canceled
	// by the caller, only by Stop itself. Before the fix, Stop only
	// canceled the in-flight GadgetContext: that made the current attempt
	// fail, but the retry loop's own context was untouched, so
	// RetryNotify started yet another attempt anyway.
	require.NoError(t, dt.Stop())

	callsAtStop := atomic.LoadInt32(&fr.calls)
	time.Sleep(1 * time.Second)
	require.Equal(t, callsAtStop, atomic.LoadInt32(&fr.calls),
		"expected no further RunGadget calls after Stop")
}

func TestDNSTracerStartStopsRetryingWhenContextCanceled(t *testing.T) {
	fr := &fakeRuntime{failCount: dnsStartMaxRetries + 10} // always fail
	dt := NewDNSTracer(nil, fr, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, dt.Start(ctx))

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&fr.calls) >= 1
	}, 5*time.Second, 10*time.Millisecond, "expected at least one attempt")

	cancel()

	callsAtCancel := atomic.LoadInt32(&fr.calls)
	time.Sleep(1 * time.Second)
	require.LessOrEqual(t, atomic.LoadInt32(&fr.calls), callsAtCancel+1,
		"expected retries to stop shortly after the context is canceled")

	require.NoError(t, dt.Stop())
}
