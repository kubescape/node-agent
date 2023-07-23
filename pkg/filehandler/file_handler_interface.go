package filehandler

import (
	"context"
	"sync"
)

type FileHandler interface {
	AddFile(ctx context.Context, bucket, file string) error
	Close()
	GetFiles(ctx context.Context, container string) (map[string]bool, *sync.RWMutex, error)
	RemoveBucket(ctx context.Context, bucket string) error
	InitBucket(ctx context.Context, bucket string)
}
