package networkmanager

import (
	"testing"

	_ "embed"

	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:embed testdata/deployment.json
var deploymentJson []byte

//go:embed testdata/daemonset.json
var daemonsetJson []byte

//go:embed testdata/pod.json
var podJson []byte

func TestGenerateNetworkNeighborsCRD(t *testing.T) {
	tests := []struct {
		name                     string
		parentWorkload           []byte
		parentWorkloadLabels     map[string]string
		expectedNetworkNeighbors *v1beta1.NetworkNeighbors
	}{
		{
			name:           "deployment",
			parentWorkload: deploymentJson,
			parentWorkloadLabels: map[string]string{
				"app": "nginx",
			},
			expectedNetworkNeighbors: &v1beta1.NetworkNeighbors{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkNeighbors",
					APIVersion: "softwarecomposition.kubescape.io/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						instanceidhandlerV1.StatusMetadataKey: "incomplete",
					},
					Name:      "deployment-nginx-deployment",
					Namespace: "default",
					Labels: map[string]string{
						"kubescape.io/workload-api-version":      "apps/v1",
						"kubescape.io/workload-namespace":        "default",
						"kubescape.io/workload-kind":             "deployment",
						"kubescape.io/workload-name":             "nginx-deployment",
						"kubescape.io/workload-resource-version": "339815",
					},
				},
				Spec: v1beta1.NetworkNeighborsSpec{
					LabelSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "nginx",
						},
					},
				},
			},
		},
		{
			name:           "daemonset",
			parentWorkload: daemonsetJson,
			parentWorkloadLabels: map[string]string{
				"match": "fluentd-elasticsearch",
			},
			expectedNetworkNeighbors: &v1beta1.NetworkNeighbors{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkNeighbors",
					APIVersion: "softwarecomposition.kubescape.io/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						instanceidhandlerV1.StatusMetadataKey: "incomplete",
					},
					Name:      "daemonset-fluentd-elasticsearch",
					Namespace: "kube-system",
					Labels: map[string]string{
						"kubescape.io/workload-api-version":      "apps/v1",
						"kubescape.io/workload-namespace":        "kube-system",
						"kubescape.io/workload-kind":             "daemonset",
						"kubescape.io/workload-name":             "fluentd-elasticsearch",
						"kubescape.io/workload-resource-version": "266406",
					},
				},
				Spec: v1beta1.NetworkNeighborsSpec{
					LabelSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"match": "fluentd-elasticsearch",
						},
					},
				},
			},
		},
		{
			name:           "pod",
			parentWorkload: podJson,
			parentWorkloadLabels: map[string]string{
				"match": "test",
			},
			expectedNetworkNeighbors: &v1beta1.NetworkNeighbors{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkNeighbors",
					APIVersion: "softwarecomposition.kubescape.io/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						instanceidhandlerV1.StatusMetadataKey: "incomplete",
					},
					Name:      "pod-nginx-deployment-fcc867f7-dgjrg",
					Namespace: "default",
					Labels: map[string]string{
						"kubescape.io/workload-api-version":      "v1",
						"kubescape.io/workload-namespace":        "default",
						"kubescape.io/workload-kind":             "pod",
						"kubescape.io/workload-name":             "nginx-deployment-fcc867f7-dgjrg",
						"kubescape.io/workload-resource-version": "339809",
					},
				},
				Spec: v1beta1.NetworkNeighborsSpec{
					LabelSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"bla3":              "blu3",
							"pod-template-hash": "fcc867f7",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wl, err := workloadinterface.NewWorkload(test.parentWorkload)
			assert.Nil(t, err)
			selector, err := wl.GetSelector()
			assert.Nil(t, err)

			actualNetworkNeighbors := generateNetworkNeighborsCRD(wl, selector)
			assert.Equal(t, test.expectedNetworkNeighbors, actualNetworkNeighbors)
		})
	}
}

func TestGenerateNetworkNeighborsNameFromWorkload(t *testing.T) {
	tests := []struct {
		name         string
		workload     []byte
		expectedName string
	}{
		{
			name:         "deployment",
			workload:     deploymentJson,
			expectedName: "deployment-nginx-deployment",
		},
		{
			name:         "daemonset",
			workload:     daemonsetJson,
			expectedName: "daemonset-fluentd-elasticsearch",
		},
		{
			name:         "pod",
			workload:     podJson,
			expectedName: "pod-nginx-deployment-fcc867f7-dgjrg",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wl, err := workloadinterface.NewWorkload(test.workload)
			assert.Nil(t, err)

			actualName := generateNetworkNeighborsNameFromWorkload(wl)
			if actualName != test.expectedName {
				t.Errorf("expected name %s, got %s", test.expectedName, actualName)
			}
		})
	}
}

func TestGenerateNetworkNeighborsNameFromWlid(t *testing.T) {
	tests := []struct {
		name         string
		parentWlid   string
		expectedName string
	}{
		{
			name:         "deployment",
			parentWlid:   "wlid://cluster-test-cluster/namespace-default/deployment-nginx-deployment",
			expectedName: "deployment-nginx-deployment",
		},
		{
			name:         "pod",
			parentWlid:   "wlid://cluster-test-cluster/namespace-default/pod-test",
			expectedName: "pod-test",
		},
		{
			name:         "daemonset",
			parentWlid:   "wlid://cluster-test-cluster/namespace-default/daemonset-test",
			expectedName: "daemonset-test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualName := generateNetworkNeighborsNameFromWlid(test.parentWlid)
			if actualName != test.expectedName {
				t.Errorf("expected name %s, got %s", test.expectedName, actualName)
			}
		})
	}
}

func TestGenerateNetworkNeighborsLabels(t *testing.T) {
	tests := []struct {
		name           string
		workload       []byte
		expectedLabels map[string]string
	}{
		{
			name:     "deployment",
			workload: deploymentJson,
			expectedLabels: map[string]string{
				"kubescape.io/workload-api-version":      "apps/v1",
				"kubescape.io/workload-namespace":        "default",
				"kubescape.io/workload-kind":             "deployment",
				"kubescape.io/workload-name":             "nginx-deployment",
				"kubescape.io/workload-resource-version": "339815",
			},
		},

		{
			name:     "daemonset",
			workload: daemonsetJson,
			expectedLabels: map[string]string{
				"kubescape.io/workload-api-version":      "apps/v1",
				"kubescape.io/workload-namespace":        "kube-system",
				"kubescape.io/workload-kind":             "daemonset",
				"kubescape.io/workload-name":             "fluentd-elasticsearch",
				"kubescape.io/workload-resource-version": "266406",
			},
		},

		{
			name:     "pod",
			workload: podJson,
			expectedLabels: map[string]string{
				"kubescape.io/workload-api-version":      "v1",
				"kubescape.io/workload-namespace":        "default",
				"kubescape.io/workload-kind":             "pod",
				"kubescape.io/workload-name":             "nginx-deployment-fcc867f7-dgjrg",
				"kubescape.io/workload-resource-version": "339809",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wl, err := workloadinterface.NewWorkload(test.workload)
			assert.Nil(t, err)

			actualLabels := generateNetworkNeighborsLabels(wl)
			if len(actualLabels) != len(test.expectedLabels) {
				t.Errorf("expected %d labels, got %d", len(test.expectedLabels), len(actualLabels))
			}

			for key, value := range test.expectedLabels {
				if actualLabels[key] != value {
					t.Errorf("expected label %s with value %s, got %s", key, value, actualLabels[key])
				}
			}
		})
	}
}

func TestFilterLabels(t *testing.T) {
	tests := []struct {
		name           string
		labels         map[string]string
		expectedLabels map[string]string
	}{
		{
			name: "one label",
			labels: map[string]string{
				"test": "1",
			},
			expectedLabels: map[string]string{
				"test": "1",
			},
		},
		{
			name: "multiple labels",
			labels: map[string]string{
				"test":  "1",
				"test2": "2",
				"test3": "3",
			},
			expectedLabels: map[string]string{
				"test":  "1",
				"test2": "2",
				"test3": "3",
			},
		},
		{
			name: "multiple labels with one ignore label",
			labels: map[string]string{
				"controller-revision-hash": "1",
				"test":                     "1",
				"test2":                    "2",
			},
			expectedLabels: map[string]string{
				"test":  "1",
				"test2": "2",
			},
		},
		{
			name: "multiple labels with multiple  ignore labels",
			labels: map[string]string{
				"controller-revision-hash": "1",
				"pod-template-generation":  "1",
				"pod-template-hash":        "1",
				"test":                     "1",
				"test2":                    "2",
				"test3":                    "3",
			},
			expectedLabels: map[string]string{
				"test":  "1",
				"test2": "2",
				"test3": "3",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualLabels := filterLabels(test.labels)
			if len(actualLabels) != len(test.expectedLabels) {
				t.Errorf("expected %d labels, got %d", len(test.expectedLabels), len(actualLabels))
			}

			for key, value := range test.expectedLabels {
				if actualLabels[key] != value {
					t.Errorf("expected label %s with value %s, got %s", key, value, actualLabels[key])
				}
			}
		})
	}
}
