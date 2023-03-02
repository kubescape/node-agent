package storageclient

type StorageHttpClient struct {
}

func CreateSBOMStorageHttpClient() *StorageHttpClient {
	return &StorageHttpClient{}
}

func (sc *StorageHttpClient) GetData(key string) ([]byte, error) {
	return nil, nil
}
func (sc *StorageHttpClient) PutData(key string, data []byte) error {
	return nil
}
func (sc *StorageHttpClient) PostData(key string, data []byte) error {
	return nil
}
