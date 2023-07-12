package sbom

import (
	"context"
	"node-agent/pkg/sbom/v1"
	"node-agent/pkg/storageclient"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/spf13/afero"
)

func TestGetSBOM(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandlerV1.InstanceID{}, afero.NewMemMapFs())
	err := SBOMClient.GetSBOM(context.TODO(), storageclient.NGINX_IMAGE_TAG, storageclient.NGINX)
	if err != nil {
		t.Fatalf("fail to get sbom, %v", err)
	}

}

func TestFilterSBOM(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandlerV1.InstanceID{}, afero.NewMemMapFs())
	err := SBOMClient.GetSBOM(context.TODO(), storageclient.NGINX_IMAGE_TAG, storageclient.NGINX)
	if err != nil {
		t.Fatalf("fail to get sbom, %v", err)
	}
	err = SBOMClient.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter sbom, %v", err)
	}

}

func TestStoreFilterSBOM(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandlerV1.InstanceID{}, afero.NewMemMapFs())
	err := SBOMClient.GetSBOM(context.TODO(), storageclient.NGINX_IMAGE_TAG, storageclient.NGINX)
	if err != nil {
		t.Fatalf("fail to get sbom")
	}
	err = SBOMClient.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter sbom")
	}
	err = SBOMClient.StoreFilterSBOM(context.TODO(), "", "anyInstanceID")
	if err != nil {
		t.Fatalf("fail to store filter sbom")
	}

}

func TestStoreFilterSBOMFailure(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateStorageHttpClientFailureMock(), "", &instanceidhandlerV1.InstanceID{}, afero.NewMemMapFs())
	err := SBOMClient.GetSBOM(context.TODO(), storageclient.NGINX_IMAGE_TAG, storageclient.NGINX)
	if err != nil {
		t.Fatalf("fail to get sbom")
	}
	err = SBOMClient.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter sbom")
	}
	err = SBOMClient.StoreFilterSBOM(context.TODO(), "", "anyInstanceID")
	if err == nil {
		t.Fatalf("StoreFilterSBOM should fail")
	}

}

func TestSBOMStructure_IsSBOMAlreadyExist(t *testing.T) {
	type fields struct {
		storageClient SBOMStorageClient
		SBOMData      sbom.SBOMFormat
		firstReport   bool
		wlid          string
		instanceID    instanceidhandler.IInstanceID
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "SBOM not already exist",
			fields: fields{
				SBOMData: &sbom.SBOMData{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SBOMStructure{
				storageClient: tt.fields.storageClient,
				SBOMData:      tt.fields.SBOMData,
				firstReport:   tt.fields.firstReport,
				wlid:          tt.fields.wlid,
				instanceID:    tt.fields.instanceID,
			}
			if got := sc.IsSBOMAlreadyExist(); got != tt.want {
				t.Errorf("IsSBOMAlreadyExist() = %v, want %v", got, tt.want)
			}
		})
	}
}
