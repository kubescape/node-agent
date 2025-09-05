package v1

import (
	"testing"

	"github.com/anchore/syft/syft/source"
	imagedigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
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
