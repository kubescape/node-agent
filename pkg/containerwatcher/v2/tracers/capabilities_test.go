package tracers

import (
	"context"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"
)

func TestCapabilitiesFields(t *testing.T) {
	expectedFields := map[string][]string{
		"capabilities": {
			"audit",
			"cap",
			"cap_effective",
			"cap_effective_raw",
			"cap_raw",
			"capable",
			"current_userns",
			"insetid",
			"kstack",
			"kstack_raw",
			"proc",
			"proc.comm",
			"proc.creds",
			"proc.creds.gid",
			"proc.creds.uid",
			"proc.mntns_id",
			"proc.parent",
			"proc.parent.comm",
			"proc.parent.pid",
			"proc.pid",
			"proc.tid",
			"syscall_raw",
			"target_userns",
			"timestamp_raw",
			"ustack",
			"ustack.base_addr_hash",
			"ustack.inode",
			"ustack.major",
			"ustack.minor",
			"ustack.mtime_nsec",
			"ustack.mtime_sec",
			"ustack.pid_level0",
			"ustack.pid_level1",
			"ustack.pidns_level0",
			"ustack.pidns_level1",
			"ustack.stack_id",
			"ustack.tgid_level0",
		},
	}
	ociStore, err := orasoci.NewFromTar(context.Background(), "../../../../tracers.tar")
	require.NoError(t, err)
	gadgetCtx := gadgetcontext.New(
		context.TODO(),
		// This is the image that contains the gadget we want to run.
		capabilitiesImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
		),
		gadgetcontext.WithName(capabilitiesTraceName),
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
		assert.Equal(t, len(fields), len(actualDS.Fields()), "data source %q has unexpected number of fields", name)
		for _, field := range fields {
			assert.NotNilf(t, actualDS.GetField(field), "field %q not found in data source %q", field, name)
		}
	}
}
