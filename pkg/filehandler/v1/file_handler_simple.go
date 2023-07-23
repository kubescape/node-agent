package filehandler

import (
	"context"
	"fmt"
	"node-agent/pkg/filehandler"
	"sync"
)

type SimapleFileHandler struct {
	mutex sync.RWMutex
	m     map[string]map[string]bool
}

var _ filehandler.FileHandler = (*SimapleFileHandler)(nil)

func CreateSimapleFileHandler() (*SimapleFileHandler, error) {
	return &SimapleFileHandler{
		m: make(map[string]map[string]bool),
	}, nil
}

func (s *SimapleFileHandler) AddFile(ctx context.Context, bucket, file string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.m[bucket]; !ok {
		s.m[bucket] = make(map[string]bool)
	}
	s.m[bucket][file] = true
	return nil
}

func (s *SimapleFileHandler) Close() {
}

func (s *SimapleFileHandler) GetFiles(ctx context.Context, container string) (map[string]bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if c, ok := s.m[container]; ok {
		return c, nil
	}
	return map[string]bool{}, fmt.Errorf("bucket does not exist for container %s", container)
}

func (s *SimapleFileHandler) RemoveBucket(ctx context.Context, bucket string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.m, bucket)
	return nil
}
