package storage

import (
	"context"
	"reflect"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
				t.Errorf("PatchApplicationProfile() error = %v, wantErr %v", err, tt.wantErr)
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
