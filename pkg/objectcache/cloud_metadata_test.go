package objectcache

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudMetadataAnnotations(t *testing.T) {
	cloud := &armotypes.CloudMetadata{
		HostType:    "gcp",
		MachineID:   "m-1",
		ClusterName: "kind-kind",
		AccountID:   "acct",
		Region:      "us-central1",
	}

	ann := CloudMetadataAnnotations(cloud)
	require.Equal(t, map[string]string{
		helpersv1.HostTypeMetadataKey:               "gcp",
		helpersv1.HostIDMetadataKey:                 "m-1",
		helpersv1.ClusterMetadataKey:                "kind-kind",
		helpersv1.CloudAccountIdentifierMetadataKey: "acct",
		helpersv1.RegionMetadataKey:                 "us-central1",
	}, ann)

	assert.Equal(t, map[string]string{helpersv1.HostTypeMetadataKey: "gcp"}, CloudMetadataAnnotations(&armotypes.CloudMetadata{HostType: "gcp"}), "empty fields are not written")
	assert.Empty(t, CloudMetadataAnnotations(nil))
}
