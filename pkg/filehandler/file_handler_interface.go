package filehandler

import "context"

type FileHandler interface {
	AddFile(ctx context.Context, bucket, file string) error
	Close()
	GetFiles(ctx context.Context, container string) (map[string]bool, error)
	RemoveBucket(ctx context.Context, bucket string) error
}
