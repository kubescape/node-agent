package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/util/validation"
)

// NamespaceFilter is an immutable snapshot of the namespace selection policy.
// A non-empty include list takes precedence over the exclude list, as in the
// startup configuration. Namespace names are exact matches, not regexes.
type NamespaceFilter struct {
	excludeAll bool
	include    []string
	exclude    []string
}

func (f *NamespaceFilter) SkipNamespace(namespace string) bool {
	if f.excludeAll {
		return true
	}
	if len(f.include) > 0 {
		return !slices.Contains(f.include, namespace)
	}
	return slices.Contains(f.exclude, namespace)
}

// ReadNamespaceFilter reopens the path on each read so Kubernetes projected
// volume symlink replacements are observed. Both arrays are required: a partial
// or malformed document must not accidentally broaden monitoring.
func ReadNamespaceFilter(path string) (*NamespaceFilter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read namespace filter: %w", err)
	}
	var document struct {
		Include *[]string `json:"includeNamespaces"`
		Exclude *[]string `json:"excludeNamespaces"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode namespace filter: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("namespace filter must contain one JSON object")
	}
	if document.Include == nil || document.Exclude == nil {
		return nil, fmt.Errorf("namespace filter requires includeNamespaces and excludeNamespaces arrays")
	}
	for _, names := range [][]string{*document.Include, *document.Exclude} {
		for _, name := range names {
			if errors := validation.IsDNS1123Label(name); len(errors) != 0 {
				return nil, fmt.Errorf("invalid namespace %q: %v", name, errors)
			}
		}
	}
	return &NamespaceFilter{include: *document.Include, exclude: *document.Exclude}, nil
}

// InitializeNamespaceFilter must run before Config is copied to managers. An
// explicitly configured file must be valid at startup; otherwise startup fails.
func (c *Config) InitializeNamespaceFilter() error {
	if c.NamespaceFilterFile == "" {
		return nil
	}
	filter, err := ReadNamespaceFilter(c.NamespaceFilterFile)
	if err != nil {
		return err
	}
	c.namespaceFilter = &atomic.Pointer[NamespaceFilter]{}
	c.namespaceFilter.Store(filter)
	return nil
}

// NamespaceFilterSnapshot returns the current immutable filter.
func (c *Config) NamespaceFilterSnapshot() *NamespaceFilter {
	if c.namespaceFilter != nil {
		return c.namespaceFilter.Load()
	}
	return &NamespaceFilter{include: slices.Clone(c.IncludeNamespaces), exclude: slices.Clone(c.ExcludeNamespaces)}
}

// ReloadNamespaceFilter atomically replaces both lists. Invalid updates leave
// the last valid snapshot intact. This is called by the container watcher's
// single reload loop, never by event-processing goroutines.
func (c *Config) ReloadNamespaceFilter() (bool, error) {
	if c.namespaceFilter == nil {
		return false, nil
	}
	next, err := ReadNamespaceFilter(c.NamespaceFilterFile)
	if err != nil {
		return false, err
	}
	current := c.namespaceFilter.Load()
	if slices.Equal(current.include, next.include) && slices.Equal(current.exclude, next.exclude) {
		return false, nil
	}
	c.namespaceFilter.Store(next)
	return true, nil
}

// UnionExclusions retains namespaces excluded by either snapshot. The reload
// loop uses this while retrying discovery, so newer edits can still take effect
// without forgetting earlier exclusion-to-inclusion transitions.
func (f *NamespaceFilter) UnionExclusions(other *NamespaceFilter) *NamespaceFilter {
	if f.excludeAll || other.excludeAll {
		return &NamespaceFilter{excludeAll: true}
	}
	if len(f.include) == 0 && len(other.include) == 0 {
		excluded := append(slices.Clone(f.exclude), other.exclude...)
		slices.Sort(excluded)
		return &NamespaceFilter{exclude: slices.Compact(excluded)}
	}
	candidates, remaining := f.include, other
	if len(candidates) == 0 {
		candidates, remaining = other.include, f
	}
	var included []string
	for _, name := range candidates {
		if !remaining.SkipNamespace(name) {
			included = append(included, name)
		}
	}
	return &NamespaceFilter{include: included, excludeAll: len(included) == 0}
}
