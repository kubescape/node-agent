package containerprofilemanager

import "errors"

var (
	ErrContainerNotFound        = errors.New("container not found")
	ContainerHasTerminatedError = errors.New("container has terminated")
	ContainerReachedMaxTime     = errors.New("container reached max time")
	ProfileRequiresSplit        = errors.New("profile requires split")
)
