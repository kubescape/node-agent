package syftutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParallelismFromCPULimitMillis(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		wantN  int
		wantOK bool
	}{
		{name: "empty string", raw: "", wantN: 0, wantOK: false},
		{name: "whitespace only", raw: "   ", wantN: 0, wantOK: false},
		{name: "non-numeric", raw: "abc", wantN: 0, wantOK: false},
		{name: "zero millicores", raw: "0", wantN: 0, wantOK: false},
		{name: "negative millicores", raw: "-500", wantN: 0, wantOK: false},
		{name: "sub-core clamped to 1", raw: "394", wantN: 1, wantOK: true},
		{name: "999m clamped to 1", raw: "999", wantN: 1, wantOK: true},
		{name: "exact 1 core", raw: "1000", wantN: 1, wantOK: true},
		{name: "1999m floors to 1", raw: "1999", wantN: 1, wantOK: true},
		{name: "exact 2 cores", raw: "2000", wantN: 2, wantOK: true},
		{name: "2500m floors to 2", raw: "2500", wantN: 2, wantOK: true},
		{name: "trimmed whitespace", raw: "  4000\n", wantN: 4, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotN, gotOK := ParallelismFromCPULimitMillis(tt.raw)
			assert.Equal(t, tt.wantOK, gotOK)
			assert.Equal(t, tt.wantN, gotN)
		})
	}
}

func TestDiskUsage(t *testing.T) {
	assert.Equal(t, int64(0), diskUsage(filepath.Join(t.TempDir(), "does-not-exist")))

	root := t.TempDir()
	sub := filepath.Join(root, "subdir")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.bin"), make([]byte, 12), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "b.bin"), make([]byte, 28), 0o600))

	assert.Equal(t, int64(40), diskUsage(root))
}

func TestDocumentConverters(t *testing.T) {
	assert.Nil(t, toELFSecurityFeatures(nil))
	assert.Nil(t, toExecutable(nil))
	assert.Nil(t, toFileLicenseEvidence(nil))
	assert.Nil(t, toFileMetadataEntry(nil))

	stackCanary := true
	pie := false
	elfFeat := toELFSecurityFeatures(&file.ELFSecurityFeatures{
		SymbolTableStripped:           true,
		StackCanary:                   &stackCanary,
		NoExecutable:                  true,
		RelocationReadOnly:            file.FullRELRO,
		PositionIndependentExecutable: &pie,
		DynamicSharedObject:           true,
	})
	require.NotNil(t, elfFeat)
	assert.True(t, elfFeat.SymbolTableStripped)
	assert.Equal(t, &stackCanary, elfFeat.StackCanary)
	assert.Equal(t, v1beta1.RelocationReadOnly(file.FullRELRO), elfFeat.RelocationReadOnly)

	exec := toExecutable(&file.Executable{
		Format:            file.ELF,
		HasExports:        true,
		HasEntrypoint:     true,
		ImportedLibraries: []string{"libc.so.6"},
	})
	require.NotNil(t, exec)
	assert.Equal(t, v1beta1.ExecutableFormat(file.ELF), exec.Format)
	assert.Equal(t, []string{"libc.so.6"}, exec.ImportedLibraries)

	ev := toFileLicenseEvidence(&model.FileLicenseEvidence{
		Confidence: 95,
		Offset:     10,
		Extent:     200,
	})
	require.NotNil(t, ev)
	assert.Equal(t, int64(95), ev.Confidence)
	assert.Equal(t, int64(10), ev.Offset)
	assert.Equal(t, int64(200), ev.Extent)

	meta := toFileMetadataEntry(&model.FileMetadataEntry{
		Mode:            755,
		Type:            "RegularFile",
		LinkDestination: "/bin/busybox",
		UserID:          0,
		GroupID:         0,
		MIMEType:        "application/x-executable",
		Size:            4096,
	})
	require.NotNil(t, meta)
	assert.Equal(t, int64(755), meta.Mode)
	assert.Equal(t, "RegularFile", meta.Type)
	assert.Equal(t, int64(4096), meta.Size_)

	digests := toDigests([]file.Digest{{Algorithm: "sha256", Value: "deadbeef"}})
	require.Len(t, digests, 1)
	assert.Equal(t, "sha256", digests[0].Algorithm)
	assert.Equal(t, "deadbeef", digests[0].Value)

	rels := toSyftRelationships([]model.Relationship{{Parent: "p1", Child: "c1", Type: "contains"}})
	require.Len(t, rels, 1)
	assert.Equal(t, "p1", rels[0].Parent)
	assert.Equal(t, "c1", rels[0].Child)

	doc := ToSyftDocument(&sbom.SBOM{})
	assert.NotEmpty(t, doc.Schema.Version)
}
