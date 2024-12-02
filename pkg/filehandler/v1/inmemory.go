package filehandler

import (
	"fmt"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/filehandler"
)

const initFileListLength = 500
const updateFileListLength = 20

type filesBucket struct {
	lock  *sync.RWMutex
	files map[string]bool
}

type InMemoryFileHandler struct {
	mutex   sync.RWMutex
	buckets map[string]*filesBucket
}

var _ filehandler.FileHandler = (*InMemoryFileHandler)(nil)

func CreateInMemoryFileHandler() (*InMemoryFileHandler, error) {
	return &InMemoryFileHandler{
		buckets: make(map[string]*filesBucket, 10),
	}, nil
}

func (s *InMemoryFileHandler) AddFile(bucket, file string) {
	// Acquire a read lock first
	s.mutex.RLock()
	bucketFiles, ok := s.buckets[bucket]
	s.mutex.RUnlock()

	// If the bucket doesn't exist, acquire a write lock to create the new bucket
	if !ok {
		s.mutex.Lock()
		// Double-check the bucket's existence to ensure another goroutine didn't already create it
		bucketFiles, ok = s.buckets[bucket]
		if !ok {
			bucketFiles = &filesBucket{
				lock:  &sync.RWMutex{},
				files: make(map[string]bool, initFileListLength),
			}
			s.buckets[bucket] = bucketFiles
			logger.L().Debug("Created new bucket", helpers.String("bucket", bucket))
		}
		s.mutex.Unlock()
	}

	// Acquire a write lock if the bucket already exists
	bucketFiles.lock.Lock()
	bucketFiles.files[file] = true
	bucketFiles.lock.Unlock()
}

func shallowCopyMapStringBool(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	mCopy := make(map[string]bool, len(m))
	for k, v := range m {
		mCopy[k] = v
	}
	return mCopy
}

// GetAndDeleteFiles returns a list of files for a container and purges the list for InMemoryFileHandler
func (s *InMemoryFileHandler) GetAndDeleteFiles(bucket string) (map[string]bool, error) {
	s.mutex.RLock()
	bucketFiles, ok := s.buckets[bucket]
	s.mutex.RUnlock()

	if !ok {
		return map[string]bool{}, fmt.Errorf("bucket does not exist for container %s", bucket)
	}

	bucketFiles.lock.Lock()
	shallow := shallowCopyMapStringBool(bucketFiles.files)
	bucketFiles.files = make(map[string]bool, updateFileListLength)
	bucketFiles.lock.Unlock()

	return shallow, nil
}

func (s *InMemoryFileHandler) RemoveBucket(bucket string) error {
	s.mutex.Lock()
	delete(s.buckets, bucket)
	s.mutex.Unlock()

	return nil
}

func (s *InMemoryFileHandler) AddFiles(bucket string, files map[string]bool) error {
	// Acquire a read lock first
	s.mutex.RLock()
	bucketFiles, ok := s.buckets[bucket]
	s.mutex.RUnlock()

	// If the bucket doesn't exist, acquire a write lock to create the new bucket
	if !ok {
		s.mutex.Lock()
		// Double-check the bucket's existence to ensure another goroutine didn't already create it
		bucketFiles, ok = s.buckets[bucket]
		if !ok {
			bucketFiles = &filesBucket{
				lock:  &sync.RWMutex{},
				files: make(map[string]bool, initFileListLength),
			}
			s.buckets[bucket] = bucketFiles
			logger.L().Debug("Created new bucket", helpers.String("bucket", bucket))
		}
		s.mutex.Unlock()
	}

	// Acquire a write lock if the bucket already exists
	bucketFiles.lock.Lock()
	for file := range files {
		bucketFiles.files[file] = true
	}
	bucketFiles.lock.Unlock()

	return nil
}
