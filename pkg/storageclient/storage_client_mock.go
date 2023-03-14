package storageclient

import (
	"encoding/json"
	"os"
	"path"
	"sniffer/pkg/utils"

	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type StorageHttpClientMock struct {
	nginxSBOMSpdxBytes *spdxv1beta1.SBOMSPDXv2p3
}

const (
	NGINX = "6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
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

func (sc *StorageHttpClientMock) GetData(key string) (any, error) {
	if key == NGINX {
		return sc.nginxSBOMSpdxBytes, nil
	}
	return nil, nil
}
func (sc *StorageHttpClientMock) PutData(key string, data any) error {
	return nil
}
func (sc *StorageHttpClientMock) PostData(key string, data any) error {
	return nil
}
