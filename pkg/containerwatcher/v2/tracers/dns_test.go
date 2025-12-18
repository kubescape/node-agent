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

func TestDnsFields(t *testing.T) {
	expectedFields := map[string][]string{
		"dns": {
			"addresses",
			"cwd",
			"data",
			"data_len",
			"dns_off",
			"dst",
			"dst.addr_raw",
			"dst.addr_raw.v4",
			"dst.addr_raw.v6",
			"dst.port",
			"dst.proto_raw",
			"dst.version",
			"exepath",
			"id",
			"latency_ns_raw",
			"name",
			"nameserver",
			"nameserver.addr_raw",
			"nameserver.addr_raw.v4",
			"nameserver.addr_raw.v6",
			"nameserver.version",
			"netns_id",
			"num_answers",
			"pkt_type",
			"pkt_type_raw",
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
			"qr",
			"qr_raw",
			"qtype",
			"qtype_raw",
			"ra",
			"rcode",
			"rcode_raw",
			"rd",
			"src",
			"src.addr_raw",
			"src.addr_raw.v4",
			"src.addr_raw.v6",
			"src.port",
			"src.proto_raw",
			"src.version",
			"tc",
			"timestamp_raw",
		},
	}
	ociStore, err := orasoci.NewFromTar(context.Background(), "../../../../tracers.tar")
	require.NoError(t, err)
	gadgetCtx := gadgetcontext.New(
		context.TODO(),
		// This is the image that contains the gadget we want to run.
		dnsImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
		),
		gadgetcontext.WithName(dnsTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ociStore),
	)
	operator, err := ocihandler.OciHandler.InstantiateDataOperator(gadgetCtx, api.ParamValues{
		"validate-metadata": "true",
		"pull":              "missing",
		"annotate":          "",
	})
	require.NoError(t, err)
	defer operator.Close(gadgetCtx)
	dnsOperator, err := NewDnsOperator().InstantiateDataOperator(gadgetCtx, api.ParamValues{})
	require.NoError(t, err)
	defer dnsOperator.Close(gadgetCtx)
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
