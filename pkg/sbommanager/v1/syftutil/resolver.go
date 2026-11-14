package syftutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	mapset "github.com/deckarep/golang-set/v2"
	imagedigest "github.com/opencontainers/go-digest"
)

// NodeResolver resolves files across an image's layer directories, as found
// in the container's overlay lowerdir: top layer first. A path comes from the
// highest layer that has it, and a file removed by a higher layer (whiteout or
// opaque directory) is not resolved from the layers below, so lookups see the
// image's final filesystem, like Syft's squashed scope.
type NodeResolver struct {
	layers    []imagedigest.Digest
	resolvers []file.Resolver
	// markers[i] are the whiteouts and opaque directories of layer i.
	markers []layerMarkers
}

var _ file.Resolver = (*NodeResolver)(nil)

// NewResolver builds a resolver over the layer directories in mounts (top
// layer first, digests in layers in the same order), reading each layer's
// whiteouts and opaque directories first.
func NewResolver(scope source.Scope, layers []imagedigest.Digest, mounts []string) (*NodeResolver, error) {
	markers := make([]layerMarkers, len(mounts))
	for i, path := range mounts {
		m, err := scanLayerMarkers(path)
		if err != nil {
			return nil, fmt.Errorf("unable to read whiteouts of layer %s: %w", path, err)
		}
		markers[i] = m
	}
	return newNodeResolver(scope, layers, mounts, markers)
}

// newNodeResolver builds the resolver from already-read markers, one entry
// per mount. nil means no markers at all (every layer resolves as is).
func newNodeResolver(scope source.Scope, layers []imagedigest.Digest, mounts []string, markers []layerMarkers) (*NodeResolver, error) {
	if markers == nil {
		markers = make([]layerMarkers, len(mounts))
	} else if len(markers) != len(mounts) {
		return nil, fmt.Errorf("got whiteouts for %d layers, but %d layer mounts", len(markers), len(mounts))
	}
	resolvers := make([]file.Resolver, len(mounts))
	for i, path := range mounts {
		directorySource, err := directorysource.New(directorysource.Config{
			Path: path,
			Base: path,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to create directory source: %w", err)
		}
		resolver, _ := directorySource.FileResolver(scope)
		resolvers[i] = resolver
	}
	return &NodeResolver{
		layers:    layers,
		resolvers: resolvers,
		markers:   markers,
	}, nil
}

// visible reports whether path p, found in layer i, is part of the image's
// final filesystem: it is not a whiteout marker itself, and no layer above i
// removed it.
func (n NodeResolver) visible(i int, p string) bool {
	if n.markers[i].isWhiteout(p) {
		return false
	}
	for _, above := range n.markers[:i] {
		if above.hides(p) {
			return false
		}
	}
	return true
}

// locationVisible is visible for a location: one reached through a symlink
// is checked at both its paths, since a higher layer can remove the link and
// leave its target (Syft puts the target in RealPath, the link in AccessPath).
func (n NodeResolver) locationVisible(i int, l file.Location) bool {
	if !n.visible(i, l.RealPath) {
		return false
	}
	return l.AccessPath == "" || l.AccessPath == l.RealPath || n.visible(i, l.AccessPath)
}

func (n NodeResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	for _, resolver := range n.resolvers {
		reader, err := resolver.FileContentsByLocation(location)
		if err == nil {
			return reader, nil
		}
	}
	return nil, os.ErrNotExist
}

// HasPath reports whether s exists in a layer and no higher layer removed it.
func (n NodeResolver) HasPath(s string) bool {
	for i, resolver := range n.resolvers {
		if resolver.HasPath(s) && n.visible(i, s) {
			return true
		}
	}
	return false
}

// FilesByPath returns the visible locations of paths, each from the highest
// layer that has it.
func (n NodeResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var allLocations = make([]file.Location, 0)
	added := mapset.NewThreadUnsafeSet[string]()
	for i, resolver := range n.resolvers {
		locations, _ := resolver.FilesByPath(paths...)
		if len(locations) > 0 {
			for _, location := range locations {
				if added.Contains(location.AccessPath) || !n.locationVisible(i, location) {
					continue
				}
				location.LocationData.Coordinates.FileSystemID = n.layers[i].String()
				allLocations = append(allLocations, location)
				added.Add(location.LocationData.AccessPath)
			}
		}
	}
	return allLocations, nil
}

// FilesByGlob returns the visible locations matching patterns, each path from
// the highest layer that has it.
func (n NodeResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var allLocations = make([]file.Location, 0)
	added := mapset.NewThreadUnsafeSet[string]()
	for i, resolver := range n.resolvers {
		locations, _ := resolver.FilesByGlob(patterns...)
		if len(locations) > 0 {
			for _, location := range locations {
				if added.Contains(location.AccessPath) || !n.locationVisible(i, location) {
					continue
				}
				location.LocationData.Coordinates.FileSystemID = n.layers[i].String()
				allLocations = append(allLocations, location)
				added.Add(location.LocationData.AccessPath)
			}
		}
	}
	return allLocations, nil
}

// FilesByMIMEType returns the visible locations of files with the given MIME
// types, each path from the highest layer that has it.
func (n NodeResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	var allLocations = make([]file.Location, 0)
	added := mapset.NewThreadUnsafeSet[string]()
	for i, resolver := range n.resolvers {
		locations, _ := resolver.FilesByMIMEType(types...)
		if len(locations) > 0 {
			for _, location := range locations {
				if added.Contains(location.AccessPath) || !n.locationVisible(i, location) {
					continue
				}
				location.LocationData.Coordinates.FileSystemID = n.layers[i].String()
				allLocations = append(allLocations, location)
				added.Add(location.LocationData.AccessPath)
			}
		}
	}
	return allLocations, nil
}

// RelativeFileByPath returns path from the highest layer where it is visible.
func (n NodeResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	for i, resolver := range n.resolvers {
		location := resolver.RelativeFileByPath(file.Location{}, path)
		if location != nil && n.locationVisible(i, *location) {
			location.LocationData.Coordinates.FileSystemID = n.layers[i].String()
			return location
		}
	}
	return nil
}

// AllLocations streams every visible location of every layer.
func (n NodeResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	var wg sync.WaitGroup
	for i, resolver := range n.resolvers {
		wg.Add(1)
		go func(i int, locations <-chan file.Location) {
			defer wg.Done()
			for location := range locations {
				if !n.locationVisible(i, location) {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case results <- location:
					continue
				}
			}
		}(i, resolver.AllLocations(ctx))
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func (n NodeResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	for _, resolver := range n.resolvers {
		metadata, err := resolver.FileMetadataByLocation(location)
		if err == nil {
			return metadata, nil
		}
	}
	return file.Metadata{}, os.ErrNotExist
}
