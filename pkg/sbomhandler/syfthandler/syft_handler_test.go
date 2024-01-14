package syfthandler

import (
	_ "embed"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/kollector-syft.json
var syftKollectorSBOM []byte

//go:embed testdata/kollector-syft-filtered.json
var syftKollectorSBOMfiltered []byte

func TestFilterRelevantFilesInSBOM(t *testing.T) {
	tests := []struct {
		name                   string
		syftDocInBytes         []byte
		sbomFileRelevantMap    map[string]bool
		expectedSyftDocInBytes []byte
	}{
		{
			name:           "kollector",
			syftDocInBytes: syftKollectorSBOM,
			sbomFileRelevantMap: map[string]bool{
				"/bin/busybox": true,
			},
			expectedSyftDocInBytes: syftKollectorSBOMfiltered,
		},
	}

	var syftDoc v1beta1.SyftDocument
	var expectedSyftDoc v1beta1.SyftDocument
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := json.Unmarshal(tt.syftDocInBytes, &syftDoc)
			require.NoError(t, err)
			err = json.Unmarshal(tt.expectedSyftDocInBytes, &expectedSyftDoc)
			require.NoError(t, err)

			filteredSyftDoc := filterRelevantFilesInSBOM(syftDoc, tt.sbomFileRelevantMap)

			assert.Equal(t, expectedSyftDoc, filteredSyftDoc)
		})
	}
}

//go:embed testdata/kollector-syft-crd.json
var kollectorSyftCRD []byte

func TestFilterSBOM(t *testing.T) {
	type fields struct {
		storageClient storage.StorageClient
	}
	type args struct {
		watchedContainer      *utils.WatchedContainerData
		sbomFileRelevantMap   map[string]bool
		expectedFilteredSBOMS int
		expectedFilteredFiles []string
	}
	instanceID, _ := instanceidhandler.GenerateInstanceIDFromString("apiVersion-v1/namespace-aaa/kind-deployment/name-kollector/containerName-kollector")

	var syftDoc v1beta1.SBOMSyft
	err := json.Unmarshal(kollectorSyftCRD, &syftDoc)
	assert.NoError(t, err)

	storageClient := storage.CreateSyftSBOMStorageHttpClientMock(syftDoc)
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "new relevant files - new filtered sbom",
			args: args{
				watchedContainer: &utils.WatchedContainerData{
					ContainerID: "kollector-402d69",
					ImageID:     "quay.io/kubescape/kollector@sha256:84ce233dd3256f097282ea4079e8908c5c0d0a895ae1aa9ae86e12aa74402d69",
					ImageTag:    "kollector",
					InstanceID:  instanceID,
				},
				sbomFileRelevantMap: map[string]bool{
					"/bin/busybox": true,
				},
				expectedFilteredSBOMS: 1,
				expectedFilteredFiles: []string{"/bin/busybox"},
			},
			fields: fields{
				storageClient: storageClient,
			},
		},
		{
			name: "no relevant files - no new filtered sbom",
			args: args{
				watchedContainer: &utils.WatchedContainerData{
					ContainerID: "kollector-402d69",
					ImageID:     "quay.io/kubescape/kollector@sha256:84ce233dd3256f097282ea4079e8908c5c0d0a895ae1aa9ae86e12aa74402d69",
					ImageTag:    "kollector",
					InstanceID:  instanceID,
					RelevantSyftFilesByIdentifier: map[string]bool{
						"dad6eaf501b8c3b7": true,
					},
				},
				sbomFileRelevantMap: map[string]bool{
					"/bin/busybox": true,
				},
				expectedFilteredSBOMS: 0,
				expectedFilteredFiles: []string{},
			},
			fields: fields{
				storageClient: storageClient,
			},
		},
		{
			name: "file is relevant but resource version is new - new filtered sbom",
			args: args{
				watchedContainer: &utils.WatchedContainerData{
					SBOMResourceVersion: -1,
					ContainerID:         "kollector-402d69",
					ImageID:             "quay.io/kubescape/kollector@sha256:84ce233dd3256f097282ea4079e8908c5c0d0a895ae1aa9ae86e12aa74402d69",
					ImageTag:            "kollector",
					InstanceID:          instanceID,
					RelevantSyftFilesByIdentifier: map[string]bool{
						"dad6eaf501b8c3b7": true,
					},
				},
				sbomFileRelevantMap: map[string]bool{
					"/bin/busybox": true,
				},
				expectedFilteredSBOMS: 1,
				expectedFilteredFiles: []string{"/bin/busybox"},
			},
			fields: fields{
				storageClient: storageClient,
			},
		},
	}

	for _, tt := range tests {
		storageClient.FilteredSyftSBOMs = []*v1beta1.SBOMSyftFiltered{}

		t.Run(tt.name, func(t *testing.T) {
			sc := &SyftHandler{
				storageClient: tt.fields.storageClient,
			}

			err := sc.FilterSBOM(tt.args.watchedContainer, tt.args.sbomFileRelevantMap)
			assert.NoError(t, err)

			assert.Equal(t, tt.args.expectedFilteredSBOMS, len(storageClient.FilteredSyftSBOMs))

			filesFound := 0
			for _, expectedFile := range tt.args.expectedFilteredFiles {
				for _, sbom := range storageClient.FilteredSyftSBOMs[0].Spec.Syft.Files {
					if sbom.Location.RealPath == expectedFile {
						filesFound++
					}
				}
			}
			assert.Equal(t, filesFound, len(tt.args.expectedFilteredFiles))
		})
	}
}
