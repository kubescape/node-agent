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

// TestAuditSeccompFields checks only the fields the SandboxPolicy seccomp layer
// reads; the upstream gadget owns the rest of its schema.
func TestAuditSeccompFields(t *testing.T) {
	// raw fields: node-agent runs no formatter operator
	required := []string{"syscall_raw", "code_raw", "proc.pid", "proc.comm", "proc.mntns_id"}
	ociStore, err := orasoci.NewFromTar(context.Background(), "../../../../tracers.tar")
	require.NoError(t, err)
	gadgetCtx := gadgetcontext.New(
		context.TODO(),
		auditSeccompImageName,
		gadgetcontext.WithDataOperators(ocihandler.OciHandler),
		gadgetcontext.WithName(auditSeccompTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ociStore),
	)
	operator, err := ocihandler.OciHandler.InstantiateDataOperator(gadgetCtx, api.ParamValues{
		"validate-metadata": "true",
		"pull":              "missing",
		"annotate":          "",
	})
	require.NoError(t, err)
	defer operator.Close(gadgetCtx)
	ds, exists := gadgetCtx.GetDataSources()["seccomp"]
	require.True(t, exists, "data source seccomp not found")
	for _, field := range required {
		assert.NotNilf(t, ds.GetField(field), "field %q not found", field)
	}
}
