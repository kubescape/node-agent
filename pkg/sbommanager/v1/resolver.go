package v1

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

type NodeResolver struct {
	layers    []imagedigest.Digest
	resolvers []file.Resolver
}

var _ file.Resolver = (*NodeResolver)(nil)

func NewResolver(scope source.Scope, layers []imagedigest.Digest, mounts []string) (*NodeResolver, error) {
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
	}, nil
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

func (n NodeResolver) HasPath(s string) bool {
	for _, resolver := range n.resolvers {
		if resolver.HasPath(s) {
			return true
		}
	}
	return false
}

func (n NodeResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var allLocations = make([]file.Location, 0)
	added := mapset.NewThreadUnsafeSet[string]()
	for i, resolver := range n.resolvers {
		locations, _ := resolver.FilesByPath(paths...)
		if len(locations) > 0 {
			for _, location := range locations {
				if added.Contains(location.LocationData.AccessPath) {
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

func (n NodeResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var allLocations = make([]file.Location, 0)
	added := mapset.NewThreadUnsafeSet[string]()
	for i, resolver := range n.resolvers {
		locations, _ := resolver.FilesByGlob(patterns...)
		if len(locations) > 0 {
			for _, location := range locations {
				if added.Contains(location.LocationData.AccessPath) {
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

func (n NodeResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	var allLocations = make([]file.Location, 0)
	added := mapset.NewThreadUnsafeSet[string]()
	for i, resolver := range n.resolvers {
		locations, _ := resolver.FilesByMIMEType(types...)
		if len(locations) > 0 {
			for _, location := range locations {
				if added.Contains(location.LocationData.AccessPath) {
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

func (n NodeResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	for i, resolver := range n.resolvers {
		location := resolver.RelativeFileByPath(file.Location{}, path)
		if location != nil {
			location.LocationData.Coordinates.FileSystemID = n.layers[i].String()
			return location
		}
	}
	return nil
}

func (n NodeResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	var wg sync.WaitGroup
	for _, resolver := range n.resolvers {
		wg.Add(1)
		go func(locations <-chan file.Location) {
			defer wg.Done()
			for location := range locations {
				select {
				case <-ctx.Done():
					return
				case results <- location:
					continue
				}
			}
		}(resolver.AllLocations(ctx))
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
