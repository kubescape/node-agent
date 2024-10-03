package v1

import (
	"fmt"
	"strings"
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	imagedigest "github.com/opencontainers/go-digest"
)

type NodeSource struct {
	description source.Description
	layers      []imagedigest.Digest
	mounts      []string
	resolver    file.Resolver
	mutex       *sync.Mutex
}

var _ source.Source = (*NodeSource)(nil)

func NewSource(imageName, imageDigest string, layers []imagedigest.Digest, mounts []string) *NodeSource {
	return &NodeSource{
		description: source.Description{
			ID:      strings.Replace(imageDigest, "sha256:", "", 1),
			Name:    imageName,
			Version: imageDigest,
			Metadata: source.ImageMetadata{
				UserInput:      imageName,
				ID:             "",
				ManifestDigest: "",
				MediaType:      "",
				Tags:           nil,
				Size:           0,
				Layers:         nil,
				RawManifest:    nil,
				RawConfig:      nil,
				RepoDigests:    nil,
				Architecture:   "",
				Variant:        "",
				OS:             "",
				Labels:         nil,
			},
		},
		layers: layers,
		mounts: mounts,
		mutex:  &sync.Mutex{},
	}
}

func (n *NodeSource) ID() artifact.ID {
	return artifact.ID(n.description.ID)
}

func (n *NodeSource) FileResolver(scope source.Scope) (file.Resolver, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.resolver == nil {
		var err error
		n.resolver, err = NewResolver(scope, n.layers, n.mounts)
		if err != nil {
			return nil, fmt.Errorf("unable to create file resolver: %w", err)
		}
	}

	return n.resolver, nil
}

func (n *NodeSource) Describe() source.Description {
	return n.description
}

func (n *NodeSource) Close() error {
	return nil
}
