package syftutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	imagedigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	_ "modernc.org/sqlite" // required by syft's RPM cataloger, mirrors sbom_manager.go
)

func Test_layerMarkers_hides(t *testing.T) {
	m := layerMarkers{
		whiteouts: map[string]struct{}{
			"/usr/local/lib/node_modules/npm": {},
			"/etc/old.conf":                   {},
		},
		opaque: map[string]struct{}{
			"/opt/app": {},
		},
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/local/lib/node_modules/npm", true},
		{"/usr/local/lib/node_modules/npm/package.json", true},
		{"/usr/local/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json", true},
		{"usr/local/lib/node_modules/npm/package.json", true}, // relative spelling
		{"/usr/local/lib/node_modules/npmx/package.json", false},
		{"/usr/local/lib/node_modules/corepack/package.json", false},
		{"/etc/old.conf", true},
		{"/etc/old.conf.d/x", false},
		{"/opt/app", false}, // an opaque directory itself stays
		{"/opt/app/lib/x.jar", true},
		{"/", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, m.hides(tt.path))
		})
	}
	assert.False(t, layerMarkers{}.hides("/usr/local/lib/node_modules/npm"))
}

// testDigests returns n distinct layer digests.
func testDigests(n int) []imagedigest.Digest {
	ds := make([]imagedigest.Digest, n)
	for i := range ds {
		ds[i] = imagedigest.Digest(fmt.Sprintf("sha256:%064d", i+1))
	}
	return ds
}

// newRemovedFilesFixture lays out two layer directories, top first like
// overlay's lowerdir. The base layer installs two python packages and
// /opt/app/old.txt; the top layer removes one package (whiteout) and replaces
// /opt/app (opaque directory) with /opt/app/new.txt. The markers are returned
// separately, the way scanLayerMarkers would read them from a real layer.
func newRemovedFilesFixture(t *testing.T) ([]string, []layerMarkers) {
	t.Helper()
	dir := t.TempDir()
	top, base := filepath.Join(dir, "top"), filepath.Join(dir, "base")

	writePythonPkg(t, base, "usr/lib/python3/dist-packages", "kept-pkg")
	writePythonPkg(t, base, "usr/lib/python3/dist-packages", "removed-pkg")
	writeFile(t, filepath.Join(base, "opt/app/old.txt"), "old")
	writeFile(t, filepath.Join(top, "opt/app/new.txt"), "new")

	markers := []layerMarkers{
		{
			whiteouts: map[string]struct{}{"/usr/lib/python3/dist-packages/removed-pkg-1.0.dist-info": {}},
			opaque:    map[string]struct{}{"/opt/app": {}},
		},
		{},
	}
	return []string{top, base}, markers
}

func realPaths(locations []file.Location) []string {
	paths := make([]string, 0, len(locations))
	for _, l := range locations {
		paths = append(paths, l.RealPath)
	}
	return paths
}

func Test_NodeResolver_SkipsFilesRemovedByUpperLayer(t *testing.T) {
	mounts, markers := newRemovedFilesFixture(t)
	r, err := newNodeResolver(source.SquashedScope, testDigests(2), mounts, markers)
	require.NoError(t, err)

	removedMeta := "/usr/lib/python3/dist-packages/removed-pkg-1.0.dist-info/METADATA"
	keptMeta := "/usr/lib/python3/dist-packages/kept-pkg-1.0.dist-info/METADATA"

	t.Run("FilesByGlob", func(t *testing.T) {
		locations, err := r.FilesByGlob("**/METADATA")
		require.NoError(t, err)
		paths := realPaths(locations)
		assert.Contains(t, paths, keptMeta)
		assert.NotContains(t, paths, removedMeta)
	})

	t.Run("FilesByPath", func(t *testing.T) {
		locations, err := r.FilesByPath("/opt/app/old.txt", removedMeta)
		require.NoError(t, err)
		assert.Empty(t, locations)

		locations, err = r.FilesByPath("/opt/app/new.txt", keptMeta)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"/opt/app/new.txt", keptMeta}, realPaths(locations))
	})

	t.Run("HasPath", func(t *testing.T) {
		assert.False(t, r.HasPath("/opt/app/old.txt"))
		assert.False(t, r.HasPath(removedMeta))
		assert.True(t, r.HasPath("/opt/app/new.txt"))
		assert.True(t, r.HasPath(keptMeta))
	})

	t.Run("RelativeFileByPath", func(t *testing.T) {
		assert.Nil(t, r.RelativeFileByPath(file.Location{}, "/opt/app/old.txt"))
		assert.NotNil(t, r.RelativeFileByPath(file.Location{}, "/opt/app/new.txt"))
	})

	t.Run("AllLocations", func(t *testing.T) {
		var paths []string
		for l := range r.AllLocations(t.Context()) {
			paths = append(paths, l.RealPath)
		}
		assert.Contains(t, paths, "/opt/app/new.txt")
		assert.Contains(t, paths, keptMeta)
		assert.NotContains(t, paths, "/opt/app/old.txt")
		assert.NotContains(t, paths, removedMeta)
	})
}

// Test_NodeResolver_WithoutMarkersResolvesEveryLayer is the negative control:
// the same fixture without markers resolves the removed files, which is what
// node-agent reported before it read the layers' whiteouts.
func Test_NodeResolver_WithoutMarkersResolvesEveryLayer(t *testing.T) {
	mounts, _ := newRemovedFilesFixture(t)
	r, err := newNodeResolver(source.SquashedScope, testDigests(2), mounts, nil)
	require.NoError(t, err)

	assert.True(t, r.HasPath("/opt/app/old.txt"))
	assert.True(t, r.HasPath("/usr/lib/python3/dist-packages/removed-pkg-1.0.dist-info/METADATA"))
}

// testImageStatus returns a CRI image status whose rootfs has the given
// diff-ids, base first as in the OCI config.
func testImageStatus(diffIDs []imagedigest.Digest) *runtime.ImageStatusResponse {
	ids := ""
	for i, d := range diffIDs {
		if i > 0 {
			ids += ","
		}
		ids += fmt.Sprintf("%q", d.String())
	}
	return &runtime.ImageStatusResponse{
		Image: &runtime.Image{Id: "test-image-id", RepoTags: []string{"test-image:latest"}},
		Info: map[string]string{
			"info": fmt.Sprintf(`{"imageSpec":{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[%s]}}}`, ids),
		},
	}
}

// sbomPackageNames runs a real Syft scan over src and returns the package names.
func sbomPackageNames(t *testing.T, src source.Source) []string {
	t.Helper()
	sbom, err := syft.CreateSBOM(t.Context(), src, syft.DefaultCreateSBOMConfig())
	require.NoError(t, err)
	var names []string
	for p := range sbom.Artifacts.Packages.Enumerate() {
		names = append(names, p.Name)
	}
	return names
}

// Test_NodeSource_SBOMLeavesOutPackageRemovedByUpperLayer runs a real Syft
// scan through NodeSource: a package whose files a higher layer removed is
// not in the SBOM, the others are.
func Test_NodeSource_SBOMLeavesOutPackageRemovedByUpperLayer(t *testing.T) {
	mounts, markers := newRemovedFilesFixture(t)
	diffIDs := testDigests(2) // base first
	src, err := NewSource("test-image:latest", "sha256:digest", "test-image-id", testImageStatus(diffIDs), mounts, 1<<30)
	require.NoError(t, err)
	src.resolver, err = newNodeResolver(source.SquashedScope, src.layers, src.mounts, markers)
	require.NoError(t, err)

	names := sbomPackageNames(t, src)
	assert.Contains(t, names, "kept-pkg")
	assert.NotContains(t, names, "removed-pkg")
}

func Test_scanLayerMarkers_PlainDirectoryHasNone(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "usr/bin/app"), "bin")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "opt/app"), 0o755))

	m, err := scanLayerMarkers(dir)
	require.NoError(t, err)
	assert.Empty(t, m.whiteouts)
	assert.Empty(t, m.opaque)
}

func Test_scanLayerMarkers_MissingLayerIsAnError(t *testing.T) {
	_, err := scanLayerMarkers(filepath.Join(t.TempDir(), "missing"))
	assert.Error(t, err)
}
