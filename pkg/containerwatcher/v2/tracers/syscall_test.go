package tracers

import (
	"context"
	"slices"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"
)

func TestSyscallFields(t *testing.T) {
	expectedFields := map[string][]string{
		"syscalls": {
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
