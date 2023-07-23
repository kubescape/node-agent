package filehandler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"node-agent/pkg/filehandler"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	bolt "go.etcd.io/bbolt"
	"go.opentelemetry.io/otel"
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
	_, span := otel.Tracer("").Start(ctx, "BoltFileHandler.AddFile")
	defer span.End()
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

func (b BoltFileHandler) GetFiles(ctx context.Context, container string) (map[string]bool, error) {
	_, span := otel.Tracer("").Start(ctx, "BoltFileHandler.GetFiles")
	defer span.End()
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

	// Purge the bucket
	err = b.fileDB.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(container))
		if err != nil {
			return fmt.Errorf("delete bucket: %s", err)
		}
		return nil
	})

	return fileList, err
}

func (b BoltFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	_, span := otel.Tracer("").Start(ctx, "BoltFileHandler.RemoveBucket")
	defer span.End()
	return b.fileDB.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(bucket))
		if err != nil {
			return fmt.Errorf("delete bucket: %s", err)
		}
		logger.L().Debug("deleted file bucket", helpers.String("bucket", bucket))
		return nil
	})
}

type File struct {
	// File object
	FileObject *os.File
	// Mutex for locking the file
	Lock *sync.Mutex
}

type FsFileHandler struct {
	// Map of string to File object
	fileMap map[string]*File
	Lock    *sync.Mutex
	dirPath string
}

func CreateFsFileHandler(path string) (*FsFileHandler, error) {
	return &FsFileHandler{Lock: &sync.Mutex{}, fileMap: make(map[string]*File), dirPath: path}, nil
}

func NormalizeBucketName(bucket string) string {
	return strings.ReplaceAll(bucket, "/", "_")
}

func (f *FsFileHandler) AddFile(ctx context.Context, bucket, file string) error {
	// Normalize the bucket name
	bucket = NormalizeBucketName(bucket)

	// Check if bucket exists in the map
	f.Lock.Lock()
	fileObject, ok := f.fileMap[bucket]
	if !ok {
		// If not, create a new file object and add it to the map
		fileOsObject, err := os.OpenFile(f.GetBucketFileName(bucket), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			f.Lock.Unlock()
			return err
		}
		fileObject = &File{FileObject: fileOsObject, Lock: &sync.Mutex{}}
		f.fileMap[bucket] = fileObject
	}
	f.Lock.Unlock()
	// Lock the file
	fileObject.Lock.Lock()
	fileObject.FileObject.WriteString(file + "\n")
	defer fileObject.Lock.Unlock()
	return nil
}

func (f *FsFileHandler) Close() {
	f.Lock.Lock()
	for _, file := range f.fileMap {
		file.Lock.Lock()
		name := file.FileObject.Name()
		_ = file.FileObject.Close()
		os.Remove(name)
	}

}

func (f *FsFileHandler) GetFiles(ctx context.Context, container string) (map[string]bool, error) {
	// Normalize the bucket name
	container = NormalizeBucketName(container)

	// Create a map of string to bool
	fileList := make(map[string]bool)
	// Check if bucket exists in the map
	f.Lock.Lock()
	fileObject, ok := f.fileMap[container]
	f.Lock.Unlock()
	if !ok {
		return fileList, fmt.Errorf("bucket does not exist for container %s", container)
	}

	// Lock the file
	fileObject.Lock.Lock()
	// Close the file
	fileObject.FileObject.Close()

	// Do not use defer here! It makes life much harder

	// Copy the file to a new file
	storageFileName := f.GetBucketFileName(container)
	storageFileCopyName := f.GetTempBucketFileName(container)
	// Copy the file
	err := copyFile(storageFileName, storageFileCopyName)
	if err != nil {
		fileObject.FileObject, _ = os.OpenFile(storageFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		fileObject.Lock.Unlock()
		return fileList, err
	}

	// Open the file (purge the contents)
	fileObject.FileObject, err = os.OpenFile(storageFileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fileObject.Lock.Unlock()
		return fileList, err
	}

	// Unlock the file and let other goroutines use it
	fileObject.Lock.Unlock()

	// Read the file line by line
	file, err := os.Open(storageFileCopyName)
	if err != nil {
		return fileList, err
	}
	defer file.Close()
	defer os.Remove(storageFileCopyName)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fileList[scanner.Text()] = true
	}
	if err := scanner.Err(); err != nil {
		return fileList, err
	}
	return fileList, nil
}

func (f *FsFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	// Normalize the bucket name
	bucket = NormalizeBucketName(bucket)

	// Check if bucket exists in the map
	f.Lock.Lock()
	defer f.Lock.Unlock()
	fileObject, ok := f.fileMap[bucket]
	if !ok {
		return fmt.Errorf("bucket does not exist for container %s", bucket)
	}

	// Lock the file
	fileObject.Lock.Lock()
	// Close the file
	fileObject.FileObject.Close()
	// Remove the file
	storageFileName := f.GetBucketFileName(bucket)
	err := os.Remove(storageFileName)
	// Unlock the file so other goroutines can use it
	fileObject.Lock.Unlock()
	if err != nil {
		return err
	}
	// Remove the bucket from the map
	delete(f.fileMap, bucket)
	return nil
}

func (f *FsFileHandler) GetBucketFileName(bucket string) string {
	return fmt.Sprintf("%s/%s.txt", f.dirPath, bucket)
}

func (f *FsFileHandler) GetTempBucketFileName(bucket string) string {
	// Get 8 random characters
	rand := uuid.New().String()[0:8]
	return fmt.Sprintf("%s/%s-%s.txt", f.dirPath, bucket, rand)
}

func copyFile(srcFile, dstFile string) error {
	// Open the source file for reading
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer src.Close()

	// Create the destination file
	dst, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	// Use io.Copy to copy the contents of the source file to the destination file
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}

	// Call Sync to flush writes to stable storage
	err = dst.Sync()
	if err != nil {
		return err
	}

	return nil
}
