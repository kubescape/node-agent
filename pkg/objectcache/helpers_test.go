package objectcache

import (
	"node-agent/mocks"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestListTerminatedContainers(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want []string
	}{
		{
			name: "Test with no terminated containers",
			pod:  mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx).(*corev1.Pod),
		},
		{
			name: "Test with terminated containers",
			pod:  mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection).(*corev1.Pod),
			want: []string{
				"containerd://5924eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779927",
				"containerd://725fee5efd1881b37157fded3061f2b049f6637e37ee1dcef534273d187b56d4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ListTerminatedContainers(tt.pod)
			slices.Sort(got)
			slices.Sort(tt.want)
			assert.Equal(t, tt.want, got)
		})
	}
}
func TestListContainers(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want []string
	}{
		{
			name: "Test single container",
			pod:  mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx).(*corev1.Pod),
			want: []string{"containerd://b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
		},
		{
			name: "Test many container",
			pod:  mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection).(*corev1.Pod),
			want: []string{
				"containerd://2c8cb9f14afc39390c49b53cc21da12c903460ee041839dd705881475ae92c0e",
				"containerd://5924eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779927",
				"containerd://6565eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779234",
				"containerd://725fee5efd1881b37157fded3061f2b049f6637e37ee1dcef534273d187b56d4",
				"containerd://baacccdd158dd7140c436207c7b3d12d15bd6a4313d59dbf471d835d7f2f8dee",
				"containerd://d6926a10223d03aea3da4aef78dbef02efb4c2cebf57cdb3da0ca1fcb4263383",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ListContainersIDs(tt.pod)
			slices.Sort(got)
			slices.Sort(tt.want)
			assert.Equal(t, tt.want, got)
		})
	}
}
