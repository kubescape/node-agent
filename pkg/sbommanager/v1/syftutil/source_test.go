package syftutil

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/source"
	imagedigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func Test_toLayers(t *testing.T) {
	type args struct {
		ds []imagedigest.Digest
		ms []string
	}
	tests := []struct {
		name  string
		args  args
		want  []source.LayerMetadata
		want1 int64
	}{
		{
			name: "empty",
			args: args{
				ds: []imagedigest.Digest{},
				ms: []string{},
			},
			want:  []source.LayerMetadata{},
			want1: 0,
		},
		{
			name: "multiple layers no size",
			args: args{
				ds: []imagedigest.Digest{
					imagedigest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
					imagedigest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
					imagedigest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
				},
				ms: []string{},
			},
			want: []source.LayerMetadata{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Size:      0,
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Size:      0,
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					Size:      0,
				}},
			want1: 0,
		},
		{
			name: "multiple layers nil size",
			args: args{
				ds: []imagedigest.Digest{
					imagedigest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
					imagedigest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
					imagedigest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
				},
				ms: nil,
			},
			want: []source.LayerMetadata{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Size:      0,
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Size:      0,
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					Size:      0,
				}},
			want1: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := toLayers(tt.args.ds, tt.args.ms)
			assert.Equalf(t, tt.want, got, "toLayers(%v, %v)", tt.args.ds, tt.args.ms)
			assert.Equalf(t, tt.want1, got1, "toLayers(%v, %v)", tt.args.ds, tt.args.ms)
		})
	}
}

func Test_validateDiffIDs(t *testing.T) {
	tests := []struct {
		name    string
		ds      []imagedigest.Digest
		wantErr bool
	}{
		{
			name: "valid digests",
			ds: []imagedigest.Digest{
				imagedigest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				imagedigest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			},
			wantErr: false,
		},
		{
			name:    "empty string digest (issue #853 crash input)",
			ds:      []imagedigest.Digest{""},
			wantErr: true,
		},
		{
			name:    "malformed digest with no separator",
			ds:      []imagedigest.Digest{imagedigest.Digest("deadbeef")},
			wantErr: true,
		},
		{
			name: "mixed valid and invalid digests",
			ds: []imagedigest.Digest{
				imagedigest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				imagedigest.Digest(""),
			},
			wantErr: true,
		},
		{
			name:    "empty slice",
			ds:      []imagedigest.Digest{},
			wantErr: false,
		},
		{
			name:    "nil slice",
			ds:      nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiffIDs(tt.ds)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_NewSource_InvalidDiffID(t *testing.T) {
	imageStatus := &runtime.ImageStatusResponse{
		Image: &runtime.Image{
			Id:       "myimage-id",
			RepoTags: []string{"myimage:latest"},
		},
		Info: map[string]string{
			"info": `{"imageSpec":{"rootfs":{"type":"layers","diff_ids":[""]}}}`,
		},
	}

	var src *NodeSource
	var err error
	assert.NotPanics(t, func() {
		src, err = NewSource("myimage:latest", "", "myimage-id", imageStatus, nil, 0)
	})
	assert.Nil(t, src)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid image diff-ids")
}

func Test_NewSource_LayerOrderingAndDigestSizePairing(t *testing.T) {
	// Base layer is at index 0 in OCI DiffIDs.
	// Mounts are top-first: mounts[0] is top layer, mounts[2] is base layer.
	imageStatus := &runtime.ImageStatusResponse{
		Image: &runtime.Image{
			Id:       "test-image-id",
			RepoTags: []string{"test-image:latest"},
		},
		Info: map[string]string{
			"info": `{
				"imageSpec": {
					"architecture": "amd64",
					"os": "linux",
					"rootfs": {
						"type": "layers",
						"diff_ids": [
							"sha256:1111111111111111111111111111111111111111111111111111111111111111",
							"sha256:2222222222222222222222222222222222222222222222222222222222222222",
							"sha256:3333333333333333333333333333333333333333333333333333333333333333"
						]
					}
				}
			}`,
		},
	}

	tempDir := t.TempDir()
	mountTop := tempDir + "/top"
	mountMid := tempDir + "/mid"
	mountBase := tempDir + "/base"
	require.NoError(t, os.Mkdir(mountTop, 0755))
	require.NoError(t, os.Mkdir(mountMid, 0755))
	require.NoError(t, os.Mkdir(mountBase, 0755))
	require.NoError(t, os.WriteFile(mountBase+"/file.txt", []byte("base-data"), 0644))
	mounts := []string{mountTop, mountMid, mountBase}

	src, err := NewSource("test-image:latest", "sha256:digest", "test-image-id", imageStatus, mounts, 1<<30)
	assert.NoError(t, err)
	assert.NotNil(t, src)

	// ImageMetadata.Layers must be in base-first order with matching digests
	meta := src.Describe().Metadata.(source.ImageMetadata)
	assert.Len(t, meta.Layers, 3)
	assert.Equal(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111", meta.Layers[0].Digest)
	assert.Equal(t, "sha256:2222222222222222222222222222222222222222222222222222222222222222", meta.Layers[1].Digest)
	assert.Equal(t, "sha256:3333333333333333333333333333333333333333333333333333333333333333", meta.Layers[2].Digest)
	// Base layer (Layers[0]) must pair with base mount (mounts[2]) size
	assert.Greater(t, meta.Layers[0].Size, int64(0))

	// NodeSource internal layers (used for overlay resolution) must be reversed (top-to-base)
	assert.Len(t, src.layers, 3)
	assert.Equal(t, "sha256:3333333333333333333333333333333333333333333333333333333333333333", src.layers[0].String())
	assert.Equal(t, "sha256:2222222222222222222222222222222222222222222222222222222222222222", src.layers[1].String())
	assert.Equal(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111", src.layers[2].String())
}
