package filehandler

import (
	"errors"
	"fmt"
	"node-agent/pkg/filehandler"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	bolt "go.etcd.io/bbolt"
)

type BoltFileHandler struct {
	fileDB *bolt.DB
}

var _ filehandler.FileHandler = (*BoltFileHandler)(nil)

func CreateBoltFileHandler(path string) (*BoltFileHandler, error) {
	db, err := bolt.Open(path, 0644, nil)
	if err != nil {
		return nil, err
	}
	return &BoltFileHandler{fileDB: db}, nil
}

func (b BoltFileHandler) AddFile(bucket, file string) {
	err := b.fileDB.Batch(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(file), nil)
	})
	if err != nil {
		logger.L().Error("failed to add file to container file list", helpers.Error(err), helpers.Interface("bucket", bucket), helpers.String("file", file))
	}
}

func (b BoltFileHandler) Close() {
	_ = b.fileDB.Close()
}

func (b BoltFileHandler) GetFiles(container string) (map[string]bool, error) {
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
	return fileList, err
}

func (b BoltFileHandler) RemoveBucket(bucket string) error {
	return b.fileDB.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(bucket))
		if err != nil {
			if errors.Is(err, bolt.ErrBucketNotFound) {
				return nil
			}
			return fmt.Errorf("delete bucket: %s", err)
		}
		logger.L().Debug("deleted file bucket", helpers.String("bucket", bucket))
		return nil
	})
}

func (b BoltFileHandler) AddFiles(bucket string, files map[string]bool) error {
	return b.fileDB.Batch(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		for file := range files {
			if err := b.Put([]byte(file), nil); err != nil {
				return err
			}
		}
		return nil
	})
}
