package containerprofilemanager

import "errors"

var (
	ErrContainerNotFound        = errors.New("container not found")
	ErrInvalidContainerID       = errors.New("invalid container ID")
	ContainerHasTerminatedError = errors.New("container has terminated")
	ContainerReachedMaxTime     = errors.New("container reached max time")
	ProfileRequiresSplit        = errors.New("profile requires split")
)
