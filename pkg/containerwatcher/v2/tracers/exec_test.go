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

func TestExecFields(t *testing.T) {
	expectedFields := map[string][]string{
		"exec": {
			"args",
			"args_count",
			"args_size",
			"cwd",
			"dev_major",
			"dev_minor",
			"error_raw",
			"exepath",
			"file",
			"file_from_rootfs",
			"from_rootfs",
			"fupper_layer",
			"inode",
			"loginuid",
			"parent_exepath",
			"proc",
			"proc.comm",
			"proc.creds",
			"proc.creds.gid",
			"proc.creds.uid",
			"proc.mntns_id",
			"proc.parent",
			"proc.parent.comm",
			"proc.parent.pid",
			"proc.parent.tid",
			"proc.pid",
			"proc.tid",
			"pupper_layer",
			"sessionid",
			"timestamp_raw",
			"tty",
			"upper_layer",
		},
	}
	ociStore, err := orasoci.NewFromTar(context.Background(), "../../../../tracers.tar")
	require.NoError(t, err)
	gadgetCtx := gadgetcontext.New(
		context.TODO(),
		// This is the image that contains the gadget we want to run.
		execImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
		),
		gadgetcontext.WithName(execTraceName),
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
