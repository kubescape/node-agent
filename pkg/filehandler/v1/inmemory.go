package filehandler

import (
	"context"
	"fmt"
	"node-agent/pkg/filehandler"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const initFileListLength = 5000

type InMemoryFileHandler struct {
	mutex sync.RWMutex
	m     map[string]*sync.RWMutex
	files map[string]map[string]bool
}

var _ filehandler.FileHandler = (*InMemoryFileHandler)(nil)

func CreateInMemoryFileHandler() (*InMemoryFileHandler, error) {
	return &InMemoryFileHandler{
		m:     make(map[string]*sync.RWMutex),
		files: make(map[string]map[string]bool, 20),
	}, nil
}

func (s *InMemoryFileHandler) AddFile(ctx context.Context, bucket, file string) error {

	// Acquire a read lock first
	s.mutex.RLock()
	bucketLock, ok := s.m[bucket]
	bucketFiles, okF := s.files[bucket]
	s.mutex.RUnlock()

	// If the bucket doesn't exist, acquire a write lock to create the new bucket
	if !ok || !okF {
		s.mutex.Lock()
		logger.L().Debug("Adding a bucket", helpers.String("bucket", bucket))
		// Double-check the bucket's existence to ensure another goroutine didn't already create it
		bucketLock, ok = s.m[bucket]
		if !ok {
			bucketLock = &sync.RWMutex{}
			s.m[bucket] = bucketLock
		}

		bucketFiles, okF = s.files[bucket]
		if !okF {
			bucketFiles = make(map[string]bool, initFileListLength)
			s.files[bucket] = bucketFiles
		}
		s.mutex.Unlock()
	}

	// Acquire a write lock if the bucket already exists
	bucketLock.Lock()
	defer bucketLock.Unlock()

	bucketFiles[file] = true

	return nil
}

func (s *InMemoryFileHandler) Close() {
	// Nothing to do
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

func (s *InMemoryFileHandler) GetFiles(ctx context.Context, bucket string) (map[string]bool, error) {
	logger.L().Debug("In GetFiles", helpers.String("bucket", bucket))
	s.mutex.RLock()
	bucketLock, ok := s.m[bucket]
	bucketFiles, okFiles := s.files[bucket]
	s.mutex.RUnlock()

	if !ok || !okFiles {
		return map[string]bool{}, fmt.Errorf("bucket does not exist for container %s", bucket)
	}

	bucketLock.RLock()
	defer bucketLock.RUnlock()
	logger.L().Debug("Done GetFiles", helpers.String("bucket", bucket))

	c := shallowCopyMapStringBool(bucketFiles)
	return c, nil
}
func (s *InMemoryFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	logger.L().Debug("In RemoveBucket", helpers.String("bucket", bucket))

	s.mutex.Lock()
	bucketLock, ok := s.m[bucket]
	if ok {
		bucketLock.Lock()
		defer bucketLock.Unlock()
	}

	delete(s.m, bucket)
	delete(s.files, bucket)
	s.mutex.Unlock()
	logger.L().Debug("Done RemoveBucket", helpers.String("bucket", bucket))

	return nil
}
