package storageclient

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
)

type StorageHttpClientMock struct {
}

const (
	NGINX = "nginx"
)

var nginx_SBOM_spdx_bytes []byte

func CreateSBOMStorageHttpClientMock() *StorageHttpClientMock {
	nginx_sbom_path := path.Join(currentDir(), "testdata", "nginx-spdx-format-mock.json")
	nginx_SBOM_spdx_bytes, _ = os.ReadFile(nginx_sbom_path)

	return &StorageHttpClientMock{}
}

func (sc *StorageHttpClientMock) GetData(key string) ([]byte, error) {
	if key == NGINX {
		return nginx_SBOM_spdx_bytes, nil
	}
	return nil, nil
}
func (sc *StorageHttpClientMock) PutData(key string, data []byte) error {
	return nil
}
func (sc *StorageHttpClientMock) PostData(key string, data []byte) error {
	return nil
}

func currentDir() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}
