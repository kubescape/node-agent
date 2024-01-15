package storage

import (
	"context"
	"fmt"
	"node-agent/pkg/storage"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStorageNoCache_CreateFilteredSBOM(t *testing.T) {
	type args struct {
		SBOM *v1beta1.SBOMSyftFiltered
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestCreateFilteredSBOM",
			args: args{
				SBOM: &v1beta1.SBOMSyftFiltered{
					ObjectMeta: v1.ObjectMeta{
						Name: storage.NginxKey,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, _ := CreateFakeStorageNoCache("kubescape")
			if err := sc.CreateFilteredSBOM(tt.args.SBOM); (err != nil) != tt.wantErr {
				t.Errorf("CreateFilteredSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStorageNoCache_GetSBOM(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		createSBOM bool
		name       string
		args       args
		want       *v1beta1.SBOMSyft
		wantErr    bool
	}{
		{
			name: "TestGetSBOM",
			args: args{
				name: storage.NginxKey,
			},
			createSBOM: true,
			want: &v1beta1.SBOMSyft{
				ObjectMeta: v1.ObjectMeta{
					Name:      storage.NginxKey,
					Namespace: "kubescape",
				},
			},
		},
		{
			name: "missing SBOM",
			args: args{
				name: storage.NginxKey,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, _ := CreateFakeStorageNoCache("kubescape")
			if tt.createSBOM {
				_, _ = sc.StorageClient.SBOMSyfts("kubescape").Create(context.Background(), tt.want, v1.CreateOptions{})
			}
			got, err := sc.GetSBOM(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStorageNoCache_PatchFilteredSBOM(t *testing.T) {
	type args struct {
		name string
		SBOM *v1beta1.SBOMSyftFiltered
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestPatchFilteredSBOM",
			args: args{
				name: storage.NginxKey,
				SBOM: &v1beta1.SBOMSyftFiltered{
					TypeMeta: v1.TypeMeta{
						Kind:       "SBOMSyftFiltered",
						APIVersion: "softwarecomposition.kubescape.io/v1beta1",
					},
					Spec: v1beta1.SBOMSyftSpec{
						Syft: v1beta1.SyftDocument{
							Artifacts: []v1beta1.SyftPackage{
								{
									PackageBasicData: v1beta1.PackageBasicData{
										Name: "test",
										ID:   "test",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, _ := CreateFakeStorageNoCache("kubescape")
			filteredSBOM := &v1beta1.SBOMSyftFiltered{
				ObjectMeta: v1.ObjectMeta{
					Name: tt.args.name,
				},
			}
			c, e := sc.StorageClient.SBOMSyftFiltereds("kubescape").Create(context.Background(), filteredSBOM, v1.CreateOptions{})
			if e != nil {
				t.Errorf("CreateFilteredSBOM() error = %v, wantErr %v", e, tt.wantErr)
			}
			fmt.Println(c)
			if err := sc.PatchFilteredSBOM(tt.args.name, tt.args.SBOM); (err != nil) != tt.wantErr {
				t.Errorf("PatchFilteredSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := sc.StorageClient.SBOMSyftFiltereds("kubescape").Get(context.Background(), tt.args.name, v1.GetOptions{})
			assert.NoError(t, err)
			assert.Equal(t, 1, len(got.Spec.Syft.Artifacts))
		})
	}
}
