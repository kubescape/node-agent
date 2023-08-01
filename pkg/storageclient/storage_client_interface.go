package storageclient

type StorageClient interface {
	GetData(key string) (any, error)
	PutData(key string, data any) error
	PostData(data any) error
}
