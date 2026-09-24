package syftutil

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // required by syft's RPM cataloger, mirrors sbom_manager.go
)

// writeFile creates parent dirs and writes content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// writePythonPkg lays down a python dist-info directory, which Syft's python
// cataloger picks up from a plain directory scan.
func writePythonPkg(t *testing.T, root, dir, name string) {
	t.Helper()
	base := filepath.Join(root, dir, name+"-1.0.dist-info")
	writeFile(t, filepath.Join(base, "METADATA"), "Metadata-Version: 2.1\nName: "+name+"\nVersion: 1.0\n")
	writeFile(t, filepath.Join(base, "RECORD"), "")
}

// newHostFixture builds a fake host root containing one catalogable package in
// a normal location and one inside each excluded location.
func newHostFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	writePythonPkg(t, root, "usr/lib/python3/dist-packages", "host-visible-pkg")

	// Container-runtime storage: an image layer's rootfs, exactly the kind of
	// content a naive host scan would wrongly attribute to the node.
	writePythonPkg(t, root, "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs/usr/lib/python3/dist-packages", "containerd-layer-pkg")
	writePythonPkg(t, root, "var/lib/docker/overlay2/abc/diff/usr/lib/python3/dist-packages", "docker-layer-pkg")
	writePythonPkg(t, root, "var/lib/containers/storage/overlay/abc/diff/usr/lib/python3/dist-packages", "crio-layer-pkg")
	writePythonPkg(t, root, "run/containerd/io.containerd.runtime.v2.task/k8s.io/xyz/rootfs/usr/lib/python3/dist-packages", "runtime-task-pkg")

	// Pseudo-filesystems.
	writePythonPkg(t, root, "proc/1/root/usr/lib/python3/dist-packages", "proc-pkg")
	writePythonPkg(t, root, "sys/kernel/usr/lib/python3/dist-packages", "sys-pkg")
	writePythonPkg(t, root, "dev/shm/usr/lib/python3/dist-packages", "dev-pkg")

	return root
}

// Test_NewHostSource_ExcludesContainerRuntimeStorage is the fixture-based proof:
// it runs a real Syft scan over a fake host root and asserts
// the container-runtime-storage and pseudo-filesystem packages are absent from
// the result, while an ordinary host package is present.
//
// A test that only asserted HostExclusionPatterns contains certain strings
// would pass even if the patterns were in a spelling Syft rejects or silently
// never matches -- which is precisely the failure mode here, since Syft
// requires scan-root-relative "./"-prefixed globs and errors on absolute ones.
func Test_NewHostSource_ExcludesContainerRuntimeStorage(t *testing.T) {
	root := newHostFixture(t)

	src, err := NewHostSource(root, "host-node-1", "test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	sbom, err := syft.CreateSBOM(t.Context(), src, syft.DefaultCreateSBOMConfig())
	require.NoError(t, err)

	var names []string
	for p := range sbom.Artifacts.Packages.Enumerate() {
		names = append(names, p.Name)
	}

	assert.Contains(t, names, "host-visible-pkg",
		"an ordinary host package must still be catalogued, otherwise the exclusion assertions below are vacuous")
	for _, excluded := range []string{
		"containerd-layer-pkg",
		"docker-layer-pkg",
		"crio-layer-pkg",
		"runtime-task-pkg",
		"proc-pkg",
		"sys-pkg",
		"dev-pkg",
	} {
		assert.NotContains(t, names, excluded, "excluded path leaked into the host SBOM")
	}
}

// Test_HostFixture_NegativeControl scans the same fixture with NO exclusions
// and asserts the container-runtime packages ARE found. Without this, the
// exclusion assertions above could pass simply because Syft never catalogued
// those files for an unrelated reason.
func Test_HostFixture_NegativeControl(t *testing.T) {
	root := newHostFixture(t)

	src, err := directorysource.New(directorysource.Config{Path: root})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	sbom, err := syft.CreateSBOM(t.Context(), src, syft.DefaultCreateSBOMConfig())
	require.NoError(t, err)

	var names []string
	for p := range sbom.Artifacts.Packages.Enumerate() {
		names = append(names, p.Name)
	}
	assert.Contains(t, names, "containerd-layer-pkg")
	assert.Contains(t, names, "docker-layer-pkg")
	assert.Contains(t, names, "proc-pkg")
}

// Test_NewHostSource_ExclusionsAreAcceptedBySyft pins the pattern spelling:
// Syft's directory source rejects exclusions that are not relative and
// "./"/"*/"/"**/"-prefixed, and that rejection only surfaces when the file
// resolver is built.
func Test_NewHostSource_ExclusionsAreAcceptedBySyft(t *testing.T) {
	src, err := NewHostSource(newHostFixture(t), "host-node-1", "test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	resolver, err := src.FileResolver(source.SquashedScope)
	require.NoError(t, err, "Syft rejected the exclusion patterns")
	require.NotNil(t, resolver)

	locations, err := resolver.FilesByGlob("**/METADATA")
	require.NoError(t, err)
	require.NotEmpty(t, locations, "the resolver must see the non-excluded fixture file, otherwise the assertions below are vacuous")
	for _, loc := range locations {
		assert.NotContains(t, loc.RealPath, "/var/lib/containerd/")
		assert.NotContains(t, loc.RealPath, "/proc/")
	}
}

// Test_NewHostSource_DescriptionHasNoImageMetadata proves the host source is a
// directory source, not an image one: nothing downstream may assume image
// layers, digests or tags for a host.
func Test_NewHostSource_DescriptionHasNoImageMetadata(t *testing.T) {
	root := t.TempDir()
	src, err := NewHostSource(root, "host-node-1", "v1.2.3")
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	desc := src.Describe()
	assert.Equal(t, "host-node-1", desc.Name)
	assert.Equal(t, "v1.2.3", desc.Version)
	_, isImage := desc.Metadata.(source.ImageMetadata)
	assert.False(t, isImage, "host source must not carry ImageMetadata")
	dirMeta, isDir := desc.Metadata.(source.DirectoryMetadata)
	require.True(t, isDir, "host source must carry DirectoryMetadata")
	assert.Equal(t, root, dirMeta.Path)
}

// Test_NewHostSource_DoesNotMutatePackagePatterns guards the in-place rewrite
// Syft performs on the exclusion slice it is handed: without the defensive
// clone, the second host scan of the process would run with patterns already
// prefixed by the first scan's absolute root.
func Test_NewHostSource_DoesNotMutatePackagePatterns(t *testing.T) {
	before := slices.Clone(HostExclusionPatterns)
	root := newHostFixture(t)

	for range 2 {
		src, err := NewHostSource(root, "host-node-1", "test")
		require.NoError(t, err)
		_, err = src.FileResolver(source.SquashedScope)
		require.NoError(t, err)
		require.NoError(t, src.Close())
	}

	assert.Equal(t, before, HostExclusionPatterns)
}

// Test_HostExclusionPatterns_CoverRequiredPaths documents the minimum set from
// the spec, in the scan-root-relative spelling Syft requires.
func Test_HostExclusionPatterns_CoverRequiredPaths(t *testing.T) {
	for _, required := range []string{
		"./var/lib/containerd/**",
		"./var/lib/docker/**",
		"./run/containerd/**",
		"./proc/**",
		"./sys/**",
		"./dev/**",
	} {
		assert.Contains(t, HostExclusionPatterns, required)
	}
}
