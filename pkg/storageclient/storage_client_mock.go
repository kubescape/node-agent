package storageclient

import (
	"context"
	"encoding/json"
	"fmt"
	"node-agent/pkg/utils"
	"os"
	"path"

	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type StorageHttpClientMock struct {
	nginxSBOMSpdxBytes *spdxv1beta1.SBOMSPDXv2p3
}

type StorageHttpClientFailureMock struct {
	nginxSBOMSpdxBytes *spdxv1beta1.SBOMSPDXv2p3
}

const (
	NGINX_KEY       = "nginx-c9b3ae"
	NGINX           = "6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	NGINX_IMAGE_TAG = "nginx"
)

func CreateSBOMStorageHttpClientMock() *StorageHttpClientMock {
	var data spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		return nil
	}

	return &StorageHttpClientMock{
		nginxSBOMSpdxBytes: &data,
	}
}

func (sc *StorageHttpClientMock) GetData(_ context.Context, key string) (any, error) {
	if key == NGINX_KEY {
		return sc.nginxSBOMSpdxBytes, nil
	}
	return nil, nil
}
func (sc *StorageHttpClientMock) PutData(_ context.Context, _ string, _ any) error {
	return nil
}
func (sc *StorageHttpClientMock) PostData(_ context.Context, _ any) error {
	return nil
}
func (sc *StorageHttpClientMock) GetResourceVersion(_ context.Context, _ string) string {
	return "123"
}

func CreateStorageHttpClientFailureMock() *StorageHttpClientFailureMock {
	var data spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		return nil
	}

	return &StorageHttpClientFailureMock{
		nginxSBOMSpdxBytes: &data,
	}
}

func (sc *StorageHttpClientFailureMock) GetData(_ context.Context, key string) (any, error) {
	if key == NGINX_KEY {
		return sc.nginxSBOMSpdxBytes, nil
	}
	return nil, nil
}

func (sc *StorageHttpClientFailureMock) PutData(_ context.Context, _ string, _ any) error {
	return fmt.Errorf("any")
}

func (sc *StorageHttpClientFailureMock) PostData(_ context.Context, _ any) error {
	return fmt.Errorf("error already exist")
}
func (sc *StorageHttpClientFailureMock) IsAlreadyExist(_ error) bool {
	return true
}
