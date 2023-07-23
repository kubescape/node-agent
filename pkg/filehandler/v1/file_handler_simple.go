package filehandler

import (
	"context"
	"fmt"
	"node-agent/pkg/filehandler"
	"sync"
)

type SimpleFileHandler struct {
	mutex sync.RWMutex
	m     map[string]map[string]bool
}

var _ filehandler.FileHandler = (*SimpleFileHandler)(nil)

func CreateSimpleFileHandler() (*SimpleFileHandler, error) {
	return &SimpleFileHandler{
		m: make(map[string]map[string]bool),
	}, nil
}

func (s *SimpleFileHandler) AddFile(ctx context.Context, bucket, file string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.m[bucket]; !ok {
		s.m[bucket] = make(map[string]bool)
	}
	s.m[bucket][file] = true
	return nil
}

func (s *SimpleFileHandler) Close() {
}

// deepcopy map[string]bool
func shalowCopyMapStringBool(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	mCopy := make(map[string]bool, len(m))
	for k, v := range m {
		mCopy[k] = v
	}
	return mCopy
}

func (s *SimpleFileHandler) GetFiles(ctx context.Context, container string) (map[string]bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if c, ok := s.m[container]; ok {
		return shalowCopyMapStringBool(c), nil
	}
	return map[string]bool{}, fmt.Errorf("bucket does not exist for container %s", container)
}

func (s *SimpleFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.m, bucket)
	return nil
}
