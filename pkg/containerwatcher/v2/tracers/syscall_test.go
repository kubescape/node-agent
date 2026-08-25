package tracers

import (
	"context"
	"slices"
	"testing"
	"time"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"
)

func TestSyscallTracerPollInterval(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want time.Duration
	}{
		{"unset config falls back to default", config.Config{}, defaultSyscallPollInterval},
		{"configured interval is used", config.Config{SyscallPollInterval: 5 * time.Second}, 5 * time.Second},
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
