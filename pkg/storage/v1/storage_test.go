package storage

import (
	"os"
	"reflect"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

func TestStorage_CreateContainerProfile(t *testing.T) {
	tests := []struct {
		name      string
		profile   *v1beta1.ContainerProfile
		namespace string
		wantErr   bool
	}{
		{
			name: "create basic container profile",
			profile: &v1beta1.ContainerProfile{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-container-profile",
					Annotations: map[string]string{
						"kubescape.io/instance-id": "test-instance-123",
						"kubescape.io/wlid":        "wlid://cluster-test/namespace-default/deployment-nginx",
						"kubescape.io/completion":  "complete",
						"kubescape.io/status":      "ready",
					},
					Labels: map[string]string{
						"app": "nginx",
					},
				},
				Spec: v1beta1.ContainerProfileSpec{
					Architectures: []string{"amd64"},
					ImageID:       "sha256:abc123",
					ImageTag:      "nginx:1.21",
					Capabilities:  []string{"NET_ADMIN", "SYS_ADMIN"},
					Execs: []v1beta1.ExecCalls{
						{Path: "/usr/bin/nginx"},
						{Path: "/bin/sh"},
					},
					Opens: []v1beta1.OpenCalls{
						{Path: "/etc/nginx/nginx.conf", Flags: []string{"O_RDONLY"}},
						{Path: "/var/log/nginx/access.log", Flags: []string{"O_WRONLY", "O_CREAT"}},
					},
					Syscalls: []string{"open", "read", "write", "execve"},
					Endpoints: []v1beta1.HTTPEndpoint{
						{Endpoint: "/health", Methods: []string{"GET"}},
						{Endpoint: "/api/v1", Methods: []string{"GET", "POST"}},
					},
				},
			},
			namespace: "default",
			wantErr:   false,
		},
		{
			name: "create container profile with network data",
			profile: &v1beta1.ContainerProfile{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-container-with-network",
					Annotations: map[string]string{
						"kubescape.io/instance-id": "test-instance-456",
						"kubescape.io/wlid":        "wlid://cluster-test/namespace-default/deployment-web",
					},
				},
				Spec: v1beta1.ContainerProfileSpec{
					Architectures: []string{"amd64"},
					ImageID:       "sha256:def456",
					ImageTag:      "web:latest",
					Egress: []v1beta1.NetworkNeighbor{
						{
							Type: "external",
							DNS:  "api.example.com",
							Ports: []v1beta1.NetworkPort{
								{Port: func() *int32 { p := int32(443); return &p }(), Protocol: "TCP"},
							},
						},
					},
					Ingress: []v1beta1.NetworkNeighbor{
						{
							Type: "internal",
							Ports: []v1beta1.NetworkPort{
								{Port: func() *int32 { p := int32(8080); return &p }(), Protocol: "TCP"},
							},
						},
					},
				},
			},
			namespace: "default",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a unique temporary directory for this test
			tempDir, err := os.MkdirTemp("", "fake-storage-queue-*")
			if err != nil {
				t.Fatalf("Failed to create temp directory: %v", err)
			}
			defer os.RemoveAll(tempDir) // Clean up after test

			// Override the queue directory for this test
			t.Setenv("QUEUE_DIR", tempDir)

			sc, err := CreateFakeStorage("kubescape")
			if err != nil {
				t.Fatalf("Failed to create fake storage: %v", err)
			}

			err = sc.CreateContainerProfileDirect(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateContainerProfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// For successful cases, just verify the method completed without error
			// The actual storage verification would be done in integration tests
			if !tt.wantErr {
				// Method completed successfully, no additional verification needed
			}
		})
	}
}
