package storageclient

type StorageClient interface {
	GetData(key string) (interface{}, error)
	PutData(key string, data interface{}) error
	PostData(key string, data interface{}) error
}
