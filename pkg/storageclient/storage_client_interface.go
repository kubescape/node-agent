package storageclient

import "context"

type StorageClient interface {
	GetData(ctx context.Context, key string) (any, error)
	PutData(ctx context.Context, key string, data any) error
	PostData(ctx context.Context, data any) error
	GetResourceVersion(ctx context.Context, key string) string
}
