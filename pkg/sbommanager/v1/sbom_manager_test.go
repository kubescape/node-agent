package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeimageDigest(t *testing.T) {
	tests := []struct {
		name        string
		imageDigest string
		imageName   string
		want        string
	}{
		{
			name:        "replicaset-kubevuln-666dbffc4f-kubevuln-ca1b-6f47",
			imageDigest: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageName:   "quay.io/kubescape/kubevuln:v0.3.2",
			want:        "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:        "trap",
			imageDigest: "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageName:   "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:        "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:        "trap 2",
			imageDigest: "@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageName:   "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:        "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:        "trap 3",
			imageDigest: "titi@toto@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageName:   "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:        "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:        "quay.io-kubescape-kubescape-v3.0.3-88a469",
			imageDigest: "86413975e2d0330176894e4f3f5987505ed27b1191f2537797fbbf345b88a469",
			imageName:   "quay.io/kubescape/kubescape:v3.0.3",
			want:        "quay.io/kubescape/kubescape@sha256:86413975e2d0330176894e4f3f5987505ed27b1191f2537797fbbf345b88a469",
		},
		{
			name:        "registry.k8s.io-kube-scheduler-v1.28.4-3d2c54",
			imageDigest: "sha256:05c284c929889d88306fdb3dd14ee2d0132543740f9e247685243214fc3d2c54",
			imageName:   "registry.k8s.io/kube-scheduler:v1.28.4",
			want:        "registry.k8s.io/kube-scheduler@sha256:05c284c929889d88306fdb3dd14ee2d0132543740f9e247685243214fc3d2c54",
		},
		{
			name:        "replicaset-nginx-bf5d5cf98",
			imageDigest: "sha256:28402db69fec7c17e179ea87882667f1e054391138f77ffaf0c3eb388efc3ffb",
			imageName:   "docker.io/library/nginx:latest",
			want:        "docker.io/library/nginx@sha256:28402db69fec7c17e179ea87882667f1e054391138f77ffaf0c3eb388efc3ffb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, normalizeImageID(tt.imageName, tt.imageDigest), "normalizeimageDigest(%v, %v)", tt.imageDigest, tt.imageName)
		})
	}
}
