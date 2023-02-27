package storageclient

type StorageClient interface {
	GetData(key string) ([]byte, error)
	PutData(key string, data []byte) error
	PostData(key string, data []byte) error
}
