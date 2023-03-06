package storageclient

import (
	"os"
	"path"
	"sniffer/pkg/utils"
)

type StorageHttpClientMock struct {
}

const (
	NGINX = "nginx"
)

var nginxSBOMSpdxBytes []byte

func CreateSBOMStorageHttpClientMock() *StorageHttpClientMock {
	nginxSBOMPath := path.Join(utils.CurrentDir(), "testdata", "nginx-spdx-format-mock.json")
	nginxSBOMSpdxBytes, _ = os.ReadFile(nginxSBOMPath)

	return &StorageHttpClientMock{}
}

func (sc *StorageHttpClientMock) GetData(key string) ([]byte, error) {
	if key == NGINX {
		return nginxSBOMSpdxBytes, nil
	}
	return nil, nil
}
func (sc *StorageHttpClientMock) PutData(key string, data []byte) error {
	return nil
}
func (sc *StorageHttpClientMock) PostData(key string, data []byte) error {
	return nil
}
