package sbom

import (
	"context"
	"math/rand"
	"node-agent/pkg/storageclient"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/spf13/afero"
)

func TestGetSBOM(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandler.InstanceID{}, afero.NewMemMapFs())
	err := SBOMClient.GetSBOM(context.TODO(), storageclient.NGINX_IMAGE_TAG, storageclient.NGINX)
	if err != nil {
		t.Fatalf("fail to get sbom, %v", err)
	}

}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// generate a random string of given length
func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))] //pick a random letter from the letterBytes
	}
	return string(b)
}

func TestFilterSBOM(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandler.InstanceID{}, afero.NewMemMapFs())
	err := SBOMClient.GetSBOM(context.TODO(), storageclient.NGINX_IMAGE_TAG, storageclient.NGINX)
	if err != nil {
		t.Fatalf("fail to get sbom, %v", err)
	}
	m := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		m["/tmp/"+randStringBytes(10)] = true
	}
	err = SBOMClient.FilterSBOM(context.TODO(), m)
	if err != nil {
		t.Fatalf("fail to filter sbom, %v", err)
	}

}

func TestStoreFilterSBOM(t *testing.T) {
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandler.InstanceID{}, afero.NewMemMapFs())
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
	SBOMClient := CreateSBOMStorageClient(storageclient.CreateStorageHttpClientFailureMock(), "", &instanceidhandler.InstanceID{}, afero.NewMemMapFs())
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
