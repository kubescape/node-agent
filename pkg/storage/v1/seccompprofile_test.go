package storage

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
)

func TestNewStorageSeccompProfileClient(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	client := NewStorageSeccompProfileClient(fakeClient.SpdxV1beta1())

	assert.NotNil(t, client)
	assert.NotNil(t, client.storageClient)
}

func TestCreateSeccompProfileClient_StorageBackend(t *testing.T) {
	fakeStorageClient := fake.NewSimpleClientset().SpdxV1beta1()

	client := CreateSeccompProfileClient(config.SeccompBackendStorage, fakeStorageClient, nil)

	assert.NotNil(t, client)
	_, ok := client.(*StorageSeccompProfileClient)
	assert.True(t, ok, "Expected StorageSeccompProfileClient for storage backend")
}

func TestCreateSeccompProfileClient_CRDBackend(t *testing.T) {
	// For CRD backend, we need a dynamic client
	client := CreateSeccompProfileClient(config.SeccompBackendCRD, nil, nil)

	assert.NotNil(t, client)
	_, ok := client.(*CRDSeccompProfileClient)
	assert.True(t, ok, "Expected CRDSeccompProfileClient for CRD backend")
}

func TestCreateSeccompProfileClient_EmptyBackendDefaultsToStorage(t *testing.T) {
	fakeStorageClient := fake.NewSimpleClientset().SpdxV1beta1()

	client := CreateSeccompProfileClient("", fakeStorageClient, nil)

	assert.NotNil(t, client)
	_, ok := client.(*StorageSeccompProfileClient)
	assert.True(t, ok, "Expected StorageSeccompProfileClient for empty backend (should default to storage)")
}

func TestCreateSeccompProfileClient_InvalidBackendDefaultsToStorage(t *testing.T) {
	fakeStorageClient := fake.NewSimpleClientset().SpdxV1beta1()

	client := CreateSeccompProfileClient("invalid", fakeStorageClient, nil)

	assert.NotNil(t, client)
	_, ok := client.(*StorageSeccompProfileClient)
	assert.True(t, ok, "Expected StorageSeccompProfileClient for invalid backend (should default to storage)")
}

