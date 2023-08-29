package sbomhandler

import (
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestSBOMHandler_CountImageUse(t *testing.T) {
	type args struct {
		imageID string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "TestCountImageUse",
			args: args{
				imageID: "nginx",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageClient := storage.CreateSBOMStorageHttpClientMock()
			sc := CreateSBOMHandler(storageClient)
			sc.IncrementImageUse(tt.args.imageID)
			assert.Equal(t, 1, storageClient.ImageCounters[tt.args.imageID])
			sc.IncrementImageUse(tt.args.imageID)
			assert.Equal(t, 2, storageClient.ImageCounters[tt.args.imageID])
			sc.DecrementImageUse(tt.args.imageID)
			assert.Equal(t, 1, storageClient.ImageCounters[tt.args.imageID])
		})
	}
}

func TestSBOMHandler_FilterSBOM(t *testing.T) {
	type fields struct {
		storageClient storage.StorageClient
	}
	type args struct {
		watchedContainer    *utils.WatchedContainerData
		sbomFileRelevantMap map[string]bool
	}
	instanceID, _ := instanceidhandler.GenerateInstanceIDFromString("apiVersion-v1/namespace-aaa/kind-deployment/name-redis/containerName-redis")
	storageClient := storage.CreateSBOMStorageHttpClientMock()
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "TestFilterSBOM",
			args: args{
				watchedContainer: &utils.WatchedContainerData{
					ContainerID: storage.NginxKey,
					ImageID:     storage.NginxImageID,
					ImageTag:    storage.NginxImageTag,
					InstanceID:  instanceID,
					//RelevantRealtimeFilesByPackageSourceInfo: map[string]*utils.PackageSourceInfoData{},
					RelevantRealtimeFilesBySPDXIdentifier: map[v1beta1.ElementID]bool{},
				},
				sbomFileRelevantMap: map[string]bool{
					"/usr/sbin/deluser": true,
				},
			},
			fields: fields{
				storageClient: storageClient,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SBOMHandler{
				storageClient: tt.fields.storageClient,
			}
			if err := sc.FilterSBOM(tt.args.watchedContainer, tt.args.sbomFileRelevantMap); (err != nil) != tt.wantErr {
				t.Errorf("FilterSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
			// verify files are reported
			assert.NotNil(t, storageClient.FilteredSBOMs)
			assert.Equal(t, 1, len(storageClient.FilteredSBOMs))
			assert.Equal(t, 1, len(storageClient.FilteredSBOMs[0].Spec.SPDX.Files))
			assert.Equal(t, "/usr/sbin/deluser", storageClient.FilteredSBOMs[0].Spec.SPDX.Files[0].FileName)
		})
	}
}

func Test_getLabels(t *testing.T) {
	type args struct {
		watchedContainer *utils.WatchedContainerData
	}
	instanceID, _ := instanceidhandler.GenerateInstanceIDFromString("apiVersion-v1/namespace-aaa/kind-deployment/name-redis/containerName-redis")
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "TestGetLabels",
			args: args{
				watchedContainer: &utils.WatchedContainerData{
					InstanceID: instanceID,
					Wlid:       "wlid://cluster-name/namespace-aaa/deployment-redis",
				},
			},
			want: map[string]string{
				"kubescape.io/workload-api-version":    "v1",
				"kubescape.io/workload-container-name": "redis",
				"kubescape.io/workload-kind":           "Deployment",
				"kubescape.io/workload-name":           "redis",
				"kubescape.io/workload-namespace":      "aaa",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLabels(tt.args.watchedContainer)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parsedFilesBySourceInfo(t *testing.T) {
	type args struct {
		packageSourceInfo string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "TestParsedFilesBySourceInfo",
			args: args{
				packageSourceInfo: "acquired package info from installed python package manifest file: /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA, /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD, /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/top_level.txt",
			},
			want: []string{
				"/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA",
				"/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD",
				"/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/top_level.txt",
			},
		},
		{
			name: "dotnet",
			args: args{
				packageSourceInfo: "acquired package info from dotnet project assets file: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "node",
			args: args{
				packageSourceInfo: "acquired package info from installed node module manifest file: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "python",
			args: args{
				packageSourceInfo: "acquired package info from installed python package manifest file: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "java",
			args: args{
				packageSourceInfo: "acquired package info from installed java archive: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "ruby",
			args: args{
				packageSourceInfo: "acquired package info from installed gem metadata file: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "go",
			args: args{
				packageSourceInfo: "acquired package info from go module information: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "rust",
			args: args{
				packageSourceInfo: "acquired package info from rust cargo manifest: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "php",
			args: args{
				packageSourceInfo: "acquired package info from PHP composer manifest: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "haskell",
			args: args{
				packageSourceInfo: "acquired package info from cabal or stack manifest files: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "erlang",
			args: args{
				packageSourceInfo: "acquired package info from rebar3 or mix manifest files: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "linux kernel archive",
			args: args{
				packageSourceInfo: "acquired package info from linux kernel archive: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "linux kernel module",
			args: args{
				packageSourceInfo: "acquired package info from linux kernel module files: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
		{
			name: "generic",
			args: args{
				packageSourceInfo: "acquired package info from the following paths: 123, 456",
			},
			want: []string{
				"123",
				"456",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsedFilesBySourceInfo(tt.args.packageSourceInfo)
			assert.Equal(t, tt.want, got)
		})
	}
}
