package helpers

import (
	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

type Helpers struct {
	objectCache objectcache.ObjectCache
}

func NewHelpers(objectCache objectcache.ObjectCache) *Helpers {
	return &Helpers{objectCache: objectCache}
}

func (h *Helpers) CreateCELHelperFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		getContainerMountPathsOverload(h),
	}
}

var _ CELHelperFunctionProvider = (*Helpers)(nil)
