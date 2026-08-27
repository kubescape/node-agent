package tracers

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"
)

// newSyscallEvent builds a synthetic "syscalls" datasource event carrying a single
// resolvable syscall, with the given containerID (which may be empty, to stand in for
// a host process not resolved to any container). It returns a *utils.DatasourceEvent
// ready to be passed to (*SyscallTracer).callback.
func newSyscallEvent(t *testing.T, containerID string) *utils.DatasourceEvent {
	t.Helper()

	// Find a syscall number this build can resolve, so decodeSyscalls returns a
	// non-empty list (callback returns early otherwise, before either signal fires).
	knownNumber := -1
	for i := 0; i < 512; i++ {
		if _, exist := syscalls.GetSyscallNameByNumber(i); exist {
			knownNumber = i
			break
		}
	}
	require.NotEqual(t, -1, knownNumber, "no resolvable syscall number available in this build")

	ds, err := datasource.New(datasource.TypeSingle, "syscalls")
	require.NoError(t, err)

	containerIDAcc, err := ds.AddField("runtime.containerId", api.Kind_String)
	require.NoError(t, err)
	syscallsAcc, err := ds.AddField("syscalls", api.Kind_Bytes)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, containerIDAcc.PutString(data, containerID))
	buf := make([]byte, knownNumber+1)
	buf[knownNumber] = 1
	require.NoError(t, syscallsAcc.PutBytes(data, buf))

	return &utils.DatasourceEvent{
		Data:       data,
		Datasource: ds,
		EventType:  utils.SyscallEventType,
	}
}

// TestSyscallTracerCallback verifies (armosec/private-node-agent#548's review): eventCallback
// must fire for every decoded syscall regardless of containerID, while reportSyscalls must
// only fire for a non-empty containerID (it bypasses the generic pipeline's own drop).
func TestSyscallTracerCallback(t *testing.T) {
	tests := []struct {
		name               string
		containerID        string
		wantEventCallback  bool
		wantReportSyscalls bool
	}{
		{
			name:               "empty containerID still reaches eventCallback but not reportSyscalls",
			containerID:        "",
			wantEventCallback:  true,
			wantReportSyscalls: false,
		},
		{
			name:               "non-empty containerID reaches both",
			containerID:        "container-123",
			wantEventCallback:  true,
			wantReportSyscalls: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var gotEventCallback bool
			var gotEventCallbackContainerID string
			reportSyscallsCalled := make(chan string, 1)

			st := &SyscallTracer{
				eventCallback: func(_ utils.K8sEvent, containerID string, _ uint32) {
					mu.Lock()
					defer mu.Unlock()
					gotEventCallback = true
					gotEventCallbackContainerID = containerID
				},
				reportSyscalls: func(containerID string, _ []string) {
					reportSyscallsCalled <- containerID
				},
			}

			st.callback(newSyscallEvent(t, tt.containerID))

			mu.Lock()
			assert.Equal(t, tt.wantEventCallback, gotEventCallback, "eventCallback invocation")
			if tt.wantEventCallback {
				assert.Equal(t, tt.containerID, gotEventCallbackContainerID)
			}
			mu.Unlock()

			if tt.wantReportSyscalls {
				select {
				case gotContainerID := <-reportSyscallsCalled:
					assert.Equal(t, tt.containerID, gotContainerID)
				case <-time.After(time.Second):
					t.Fatal("reportSyscalls was not called")
				}
			} else {
				select {
				case <-reportSyscallsCalled:
					t.Fatal("reportSyscalls must not be called for an empty containerID")
				case <-time.After(50 * time.Millisecond):
				}
			}
		})
	}
}

func TestSyscallTracerPollInterval(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want time.Duration
	}{
		{"unset config falls back to default", config.Config{}, config.DefaultSyscallPollInterval},
		{"configured interval is used", config.Config{SyscallPollInterval: 10 * time.Second}, 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &SyscallTracer{cfg: tt.cfg}
			assert.Equal(t, tt.want, st.pollInterval())
		})
	}
}

func TestSyscallTracerPeekDoesNotPanic(t *testing.T) {
	// With no gadget instance running, this must be a silent no-op (see
	// ebpfoperator.TriggerManualMapFetch).
	st := &SyscallTracer{}
	assert.NotPanics(t, st.Peek)
}

func TestSyscallTracerRunPeekLoopStopsOnDone(t *testing.T) {
	st := &SyscallTracer{
		cfg:  config.Config{SyscallPollInterval: 5 * time.Millisecond},
		done: make(chan struct{}),
	}

	finished := make(chan struct{})
	go func() {
		st.runPeekLoop()
		close(finished)
	}()

	// Let a few ticks fire (each a harmless no-op Peek with no gadget running) before stopping.
	time.Sleep(30 * time.Millisecond)
	close(st.done)

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("runPeekLoop did not return after done was closed")
	}
}

func TestSyscallFields(t *testing.T) {
	expectedFields := map[string][]string{
		syscallDataSourceName: {
			"mntns_id_raw",
			"syscalls",
		},
	}
	ociStore, err := orasoci.NewFromTar(context.Background(), "../../../../tracers.tar")
	require.NoError(t, err)
	gadgetCtx := gadgetcontext.New(
		context.TODO(),
		// This is the image that contains the gadget we want to run.
		syscallImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
		),
		gadgetcontext.WithName(syscallTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ociStore),
	)
	operator, err := ocihandler.OciHandler.InstantiateDataOperator(gadgetCtx, api.ParamValues{
		"validate-metadata": "true",
		"pull":              "missing",
		"annotate":          "",
	})
	require.NoError(t, err)
	defer operator.Close(gadgetCtx)
	dataSources := gadgetCtx.GetDataSources()
	for name, fields := range expectedFields {
		actualDS, exists := dataSources[name]
		require.True(t, exists, "data source %q not found", name)
		for _, field := range fields {
			assert.NotNilf(t, actualDS.GetField(field), "field %q not found in data source %q", field, name)
		}
		for _, field := range actualDS.Fields() {
			if !slices.Contains(fields, field.FullName) {
				t.Errorf("unexpected field %q in data source %q", field.FullName, name)
			}
		}
	}
}
