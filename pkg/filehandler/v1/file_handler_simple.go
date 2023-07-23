package filehandler

import (
	"context"
	"fmt"
	"node-agent/pkg/filehandler"
	"sync"
)

type SimpleFileHandler struct {
	mutex sync.RWMutex
	m     map[string]*sync.RWMutex
	files map[string]map[string]bool
}

var _ filehandler.FileHandler = (*SimpleFileHandler)(nil)

func CreateSimpleFileHandler() (*SimpleFileHandler, error) {
	return &SimpleFileHandler{
		m:     make(map[string]*sync.RWMutex),
		files: make(map[string]map[string]bool),
	}, nil
}

func (s *SimpleFileHandler) AddFile(ctx context.Context, bucket, file string) error {
	// Acquire a read lock first
	s.mutex.RLock()
	bucketLock, ok := s.m[bucket]
	bucketFiles, okF := s.files[bucket]
	s.mutex.RUnlock()

	// If the bucket doesn't exist, acquire a write lock to create the new bucket
	if !ok || !okF {
		s.mutex.Lock()

		// Double-check the bucket's existence to ensure another goroutine didn't already create it
		bucketLock, ok = s.m[bucket]
		if !ok {
			bucketLock = &sync.RWMutex{}
			s.m[bucket] = bucketLock
		}

		bucketFiles, okF = s.files[bucket]
		if !okF {
			bucketFiles = make(map[string]bool)
			s.files[bucket] = bucketFiles
		}

	}

	// Acquire a write lock if the bucket already exists
	bucketLock.Lock()
	defer bucketLock.Unlock()

	bucketFiles[file] = true

	return nil
}

func (s *SimpleFileHandler) Close() {
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

func (s *SimpleFileHandler) GetFiles(ctx context.Context, bucket string) (map[string]bool, error) {
	s.mutex.RLock()
	bucketLock, ok := s.m[bucket]
	bucketFiles, okFiles := s.files[bucket]
	s.mutex.RUnlock()

	if !ok || !okFiles {
		return map[string]bool{}, fmt.Errorf("bucket does not exist for container %s", bucket)
	}

	bucketLock.RLock()
	defer bucketLock.RUnlock()

	return shallowCopyMapStringBool(bucketFiles), nil
}
func (s *SimpleFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	s.mutex.Lock()
	bucketLock, ok := s.m[bucket]
	if ok {
		bucketLock.Lock()
		defer bucketLock.Unlock()
	}

	delete(s.m, bucket)
	delete(s.files, bucket)
	s.mutex.Unlock()

	return nil
}
