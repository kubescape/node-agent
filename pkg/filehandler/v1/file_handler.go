package filehandler

import (
	"context"
	"fmt"
	"node-agent/pkg/filehandler"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	bolt "go.etcd.io/bbolt"
)

type BoltFileHandler struct {
	fileDB *bolt.DB
}

var _ filehandler.FileHandler = (*BoltFileHandler)(nil)

func CreateBoltFileHandler() (*BoltFileHandler, error) {
	db, err := bolt.Open("/data/file.db", 0644, nil)
	if err != nil {
		return nil, err
	}
	return &BoltFileHandler{fileDB: db}, nil
}

func (b BoltFileHandler) AddFile(ctx context.Context, bucket, file string) error {
	// _, span := otel.Tracer("").Start(ctx, "BoltFileHandler.AddFile")
	// defer span.End()
	return b.fileDB.Batch(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(file), nil)
	})
}

func (b BoltFileHandler) Close() {
	_ = b.fileDB.Close()
}

func (b BoltFileHandler) GetFiles(ctx context.Context, container string) (map[string]bool, *sync.RWMutex, error) {
	// _, span := otel.Tracer("").Start(ctx, "BoltFileHandler.GetFiles")
	// defer span.End()
	fileList := make(map[string]bool)
	err := b.fileDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(container))
		if b == nil {
			return fmt.Errorf("bucket does not exist for container %s", container)
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			fileList[string(k)] = true
		}
		return nil
	})
	return fileList, nil, err
}

func (b BoltFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	// _, span := otel.Tracer("").Start(ctx, "BoltFileHandler.RemoveBucket")
	// defer span.End()
	return b.fileDB.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(bucket))
		if err != nil {
			return fmt.Errorf("delete bucket: %s", err)
		}
		logger.L().Debug("deleted file bucket", helpers.String("bucket", bucket))
		return nil
	})
}

func (b BoltFileHandler) InitBucket(ctx context.Context, bucket string) {
	// Do nothing
}
