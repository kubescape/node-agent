package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	imagedigest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var (
	ErrImageTooLarge = errors.New("image size exceeds maximum allowed size")
)

type NodeSource struct {
	description source.Description
	layers      []imagedigest.Digest
	mounts      []string
	resolver    file.Resolver
	mutex       *sync.Mutex
}

var _ source.Source = (*NodeSource)(nil)

type ImageInfo struct {
	ImageSpec imagespec.Image `json:"imageSpec"`
}

func NewSource(imageName, imageDigest, imageID string, imageStatus *runtime.ImageStatusResponse, mounts []string, maxImageSize int64) (*NodeSource, error) {
	// unmarshal image info
	var imageInfo ImageInfo
	err := json.Unmarshal([]byte(imageStatus.Info["info"]), &imageInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal image info: %w", err)
	}
	reverseLayers := imageInfo.ImageSpec.RootFS.DiffIDs
	// reverse layers to match the order of the mounts
	slices.Reverse(reverseLayers)
	// prepare image config
	configFile := v1.ConfigFile{
		Architecture:  imageInfo.ImageSpec.Architecture,
		Author:        imageInfo.ImageSpec.Author,
		Container:     "",
		Created:       toTime(imageInfo.ImageSpec.Created),
		DockerVersion: "",
		History:       toHistory(imageInfo.ImageSpec.History),
		OS:            imageInfo.ImageSpec.OS,
		RootFS:        toRootFS(imageInfo.ImageSpec.RootFS),
		Config:        toConfig(imageInfo.ImageSpec.Config),
		OSVersion:     imageInfo.ImageSpec.Platform.OSVersion,
		Variant:       imageInfo.ImageSpec.Platform.Variant,
		OSFeatures:    imageInfo.ImageSpec.Platform.OSFeatures,
	}
	rawConfig, err := json.Marshal(configFile)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal image config: %w", err)
	}
	layers, totalSize := toLayers(imageInfo.ImageSpec.RootFS.DiffIDs, mounts)
	// check total size
	if totalSize > maxImageSize {
		return nil, ErrImageTooLarge
	}
	return &NodeSource{
		description: source.Description{
			ID:      strings.Replace(imageDigest, "sha256:", "", 1),
			Name:    imageName,
			Version: imageDigest,
			Metadata: source.ImageMetadata{
				UserInput:      imageID,
				ID:             imageStatus.Image.Id,
				ManifestDigest: "",
				MediaType:      "",
				Tags:           imageStatus.Image.RepoTags,
				Size:           totalSize,
				Layers:         layers,
				RawManifest:    nil,
				RawConfig:      rawConfig,
				RepoDigests:    imageStatus.Image.RepoDigests,
				Architecture:   imageInfo.ImageSpec.Architecture,
				Variant:        imageInfo.ImageSpec.Variant,
				OS:             imageInfo.ImageSpec.OS,
				Labels:         imageInfo.ImageSpec.Config.Labels,
			},
		},
		layers: reverseLayers,
		mounts: mounts,
		mutex:  &sync.Mutex{},
	}, nil
}

func toConfig(config imagespec.ImageConfig) v1.Config {
	return v1.Config{
		AttachStderr: false,
		AttachStdin:  false,
		AttachStdout: false,
		Cmd:          config.Cmd,
		Healthcheck: &v1.HealthConfig{
			Test:        nil,
			Interval:    0,
			Timeout:     0,
			StartPeriod: 0,
			Retries:     0,
		},
		Domainname:      "",
		Entrypoint:      config.Entrypoint,
		Env:             config.Env,
		Hostname:        "",
		Image:           "",
		Labels:          config.Labels,
		OnBuild:         nil,
		OpenStdin:       false,
		StdinOnce:       false,
		Tty:             false,
		User:            "",
		Volumes:         config.Volumes,
		WorkingDir:      config.WorkingDir,
		ExposedPorts:    config.ExposedPorts,
		ArgsEscaped:     config.ArgsEscaped,
		NetworkDisabled: false,
		MacAddress:      "",
		StopSignal:      config.StopSignal,
		Shell:           nil,
	}
}

func toDiffIDs(ds []imagedigest.Digest) []v1.Hash {
	hashes := make([]v1.Hash, len(ds))
	for i, d := range ds {
		hashes[i] = v1.Hash{
			Algorithm: string(d.Algorithm()),
			Hex:       d.Hex(),
		}
	}
	return hashes
}

func toHistory(history []imagespec.History) []v1.History {
	histories := make([]v1.History, len(history))
	for i, h := range history {
		histories[i] = v1.History{
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			Created:    toTime(h.Created),
			EmptyLayer: h.EmptyLayer,
		}
	}
	return histories
}

func toLayers(ds []imagedigest.Digest, ms []string) ([]source.LayerMetadata, int64) {
	var totalSize int64
	layers := make([]source.LayerMetadata, len(ds))
	msLen := len(ms)
	for i, d := range ds {
		var s int64
		if msLen > i {
			s = diskUsage(ms[msLen-i-1])
			totalSize += s
		}
		layers[i] = source.LayerMetadata{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    d.String(),
			Size:      s,
		}
	}
	return layers, totalSize
}

func toRootFS(rootFS imagespec.RootFS) v1.RootFS {
	return v1.RootFS{
		Type:    rootFS.Type,
		DiffIDs: toDiffIDs(rootFS.DiffIDs),
	}
}

func toTime(created *time.Time) v1.Time {
	if created == nil {
		return v1.Time{}
	}
	return v1.Time{
		Time: *created,
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
