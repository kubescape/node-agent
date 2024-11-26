package storage

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStorage_CreateFilteredSBOM(t *testing.T) {
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
			sc, _ := CreateFakeStorage("kubescape")
			if err := sc.CreateFilteredSBOM(tt.args.SBOM); (err != nil) != tt.wantErr {
				t.Errorf("CreateFilteredSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStorage_GetSBOM(t *testing.T) {
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
			sc, _ := CreateFakeStorage("kubescape")
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

func TestStorage_PatchFilteredSBOM(t *testing.T) {
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
			sc, _ := CreateFakeStorage("kubescape")
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

func TestStorage_PatchNetworkNeighbors(t *testing.T) {
	type args struct {
		name      string
		neighbors *v1beta1.NetworkNeighbors
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				name: storage.NginxKey,
				neighbors: &v1beta1.NetworkNeighbors{
					Spec: v1beta1.NetworkNeighborsSpec{
						Ingress: []v1beta1.NetworkNeighbor{
							{
								Ports: []v1beta1.NetworkPort{
									{Name: "test2"},
									{Name: "test3"},
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
			sc, _ := CreateFakeStorage("kubescape")
			existingProfile := &v1beta1.NetworkNeighbors{
				ObjectMeta: v1.ObjectMeta{
					Name: tt.args.name,
				},
				Spec: v1beta1.NetworkNeighborsSpec{
					Ingress: []v1beta1.NetworkNeighbor{
						{
							Ports: []v1beta1.NetworkPort{
								{Name: "test"},
								{Name: "test1"},
							},
						},
					},
				},
			}
			_, _ = sc.StorageClient.NetworkNeighborses("default").Create(context.Background(), existingProfile, v1.CreateOptions{})
			if err := sc.PatchNetworkNeighborsIngressAndEgress(tt.args.name, "default", tt.args.neighbors); (err != nil) != tt.wantErr {
				t.Errorf("PatchFilteredSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := sc.StorageClient.NetworkNeighborses("default").Get(context.Background(), tt.args.name, v1.GetOptions{})
			assert.NoError(t, err)
			assert.Equal(t, 4, len(got.Spec.Ingress[0].Ports))
		})
	}
}

func TestStorage_PatchApplicationProfile(t *testing.T) {
	type args struct {
		name       string
		operations []utils.PatchOperation
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    *v1beta1.ApplicationProfile
	}{
		{
			name: "test",
			args: args{
				name: storage.NginxKey,
				operations: []utils.PatchOperation{
					{Op: "add", Path: "/spec/containers/0/capabilities/-", Value: "SYS_ADMIN"},
					{Op: "add", Path: "/spec/containers/0/execs/-", Value: v1beta1.ExecCalls{Path: "/usr/bin/test2"}},
					{Op: "add", Path: "/spec/containers/0/execs/-", Value: v1beta1.ExecCalls{Path: "/usr/bin/test3"}},
					{Op: "add", Path: "/spec/containers/0/opens/-", Value: v1beta1.OpenCalls{Path: "/usr/bin/test2"}},
					{Op: "add", Path: "/spec/containers/0/opens/-", Value: v1beta1.OpenCalls{Path: "/usr/bin/test3"}},
					{Op: "add", Path: "/spec/containers/0/syscalls/-", Value: "open"},
				},
			},
			want: &v1beta1.ApplicationProfile{
				ObjectMeta: v1.ObjectMeta{
					Name:      storage.NginxKey,
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{{
						Name:         "test",
						Capabilities: []string{"NET_ADMIN", "SYS_ADMIN"},
						Execs: []v1beta1.ExecCalls{
							{Path: "/usr/bin/test"},
							{Path: "/usr/bin/test1"},
							{Path: "/usr/bin/test2"},
							{Path: "/usr/bin/test3"},
						},
						Opens: []v1beta1.OpenCalls{
							{Path: "/usr/bin/test"},
							{Path: "/usr/bin/test1"},
							{Path: "/usr/bin/test2"},
							{Path: "/usr/bin/test3"},
						},
						Syscalls: []string{"execve", "open"},
					}},
				},
			},
		},
		{
			name: "test",
			args: args{
				name: storage.NginxKey,
				operations: []utils.PatchOperation{
					{Op: "add", Path: "/spec/initContainers", Value: []v1beta1.ApplicationProfileContainer{{}, {}, {Name: "toto"}}},
				},
			},
			want: &v1beta1.ApplicationProfile{
				ObjectMeta: v1.ObjectMeta{
					Name:      storage.NginxKey,
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{{
						Name:         "test",
						Capabilities: []string{"NET_ADMIN"},
						Execs: []v1beta1.ExecCalls{
							{Path: "/usr/bin/test"},
							{Path: "/usr/bin/test1"},
						},
						Opens: []v1beta1.OpenCalls{
							{Path: "/usr/bin/test"},
							{Path: "/usr/bin/test1"},
						},
						Syscalls: []string{"execve"},
					}},
					InitContainers: []v1beta1.ApplicationProfileContainer{{}, {}, {Name: "toto"}},
				},
			},
		},
		{
			name: "test",
			args: args{
				name: storage.NginxKey,
				operations: []utils.PatchOperation{
					{Op: "add", Path: "/spec/ephemeralContainers", Value: []v1beta1.ApplicationProfileContainer{{}, {}, {Name: "abc"}}},
				},
			},
			want: &v1beta1.ApplicationProfile{
				ObjectMeta: v1.ObjectMeta{
					Name:      storage.NginxKey,
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{{
						Name:         "test",
						Capabilities: []string{"NET_ADMIN"},
						Execs: []v1beta1.ExecCalls{
							{Path: "/usr/bin/test"},
							{Path: "/usr/bin/test1"},
						},
						Opens: []v1beta1.OpenCalls{
							{Path: "/usr/bin/test"},
							{Path: "/usr/bin/test1"},
						},
						Syscalls: []string{"execve"},
					}},
					EphemeralContainers: []v1beta1.ApplicationProfileContainer{{}, {}, {Name: "abc"}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, _ := CreateFakeStorage("kubescape")
			existingProfile := &v1beta1.ApplicationProfile{
				ObjectMeta: v1.ObjectMeta{
					Name: tt.args.name,
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name:         "test",
							Capabilities: []string{"NET_ADMIN"},
							Execs: []v1beta1.ExecCalls{
								{Path: "/usr/bin/test"},
								{Path: "/usr/bin/test1"},
							},
							Opens: []v1beta1.OpenCalls{
								{Path: "/usr/bin/test"},
								{Path: "/usr/bin/test1"},
							},
							Syscalls: []string{"execve"},
						},
					},
				},
			}
			_, _ = sc.StorageClient.ApplicationProfiles("default").Create(context.Background(), existingProfile, v1.CreateOptions{})
			if err := sc.PatchApplicationProfile(tt.args.name, "default", tt.args.operations, nil); (err != nil) != tt.wantErr {
				t.Errorf("PatchFilteredSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := sc.StorageClient.ApplicationProfiles("default").Get(context.Background(), tt.args.name, v1.GetOptions{})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetMultiplier(t *testing.T) {
	tests := []struct {
		name        string
		envMultiply string
		envPodName  string
		want        *int
	}{
		{
			name:        "MULTIPLY not true",
			envMultiply: "false",
			envPodName:  "pod-1",
			want:        nil,
		},
		{
			name:        "MULTIPLY true but pod name not properly formatted",
			envMultiply: "true",
			envPodName:  "pod",
			want:        nil,
		},
		{
			name:        "MULTIPLY true and pod name properly formatted",
			envMultiply: "true",
			envPodName:  "pod-1",
			want:        func() *int { i := 1; return &i }(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MULTIPLY", tt.envMultiply)
			t.Setenv(config.PodNameEnvVar, tt.envPodName)

			if got := getMultiplier(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getMultiplier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStorage_revertNameP(t *testing.T) {
	type fields struct {
		multiplier int
	}
	type args struct {
		n string
	}
	tests := []struct {
		name   string
		fields *fields
		args   args
		want   string
	}{
		{
			name: "Test with multiplier",
			fields: &fields{
				multiplier: 5,
			},
			args: args{
				n: "test-5",
			},
			want: "test",
		},
		{
			name:   "Test without multiplier",
			fields: nil,
			args: args{
				n: "test",
			},
			want: "test",
		},
		{
			name: "Test with different multiplier",
			fields: &fields{
				multiplier: 6,
			},
			args: args{
				n: "test-5",
			},
			want: "test-5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &Storage{}
			if tt.fields != nil {
				sc.multiplier = &tt.fields.multiplier
			}
			sc.revertNameP(&tt.args.n)
			assert.Equal(t, tt.want, tt.args.n)
		})
	}
}

func TestStorage_modifyNameP(t *testing.T) {
	type fields struct {
		multiplier int
	}
	type args struct {
		n string
	}
	tests := []struct {
		name   string
		fields *fields
		args   args
		want   string
	}{
		{
			name: "Test with multiplier",
			fields: &fields{
				multiplier: 5,
			},
			args: args{
				n: "test",
			},
			want: "test-5",
		},
		{
			name:   "Test without multiplier",
			fields: nil,
			args: args{
				n: "test",
			},
			want: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &Storage{}
			if tt.fields != nil {
				sc.multiplier = &tt.fields.multiplier
			}
			sc.modifyNameP(&tt.args.n)
			assert.Equal(t, tt.want, tt.args.n)
		})
	}
}

func TestStorage_modifyName(t *testing.T) {
	type fields struct {
		multiplier int
	}
	type args struct {
		n string
	}
	tests := []struct {
		name   string
		fields *fields
		args   args
		want   string
	}{
		{
			name: "Test with multiplier",
			fields: &fields{
				multiplier: 5,
			},
			args: args{
				n: "test",
			},
			want: "test-5",
		},
		{
			name:   "Test without multiplier",
			fields: nil,
			args: args{
				n: "test",
			},
			want: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &Storage{}
			if tt.fields != nil {
				sc.multiplier = &tt.fields.multiplier
			}
			m := sc.modifyName(tt.args.n)
			assert.Equal(t, tt.want, m)
		})
	}
}
