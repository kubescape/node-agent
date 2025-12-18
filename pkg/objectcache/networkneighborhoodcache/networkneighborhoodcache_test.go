package networkneighborhoodcache

import (
	"context"
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SpyProfileClient for testing pagination
type SpyProfileClient struct {
	storage.ProfileClient
	NetworkNeighborhoods []v1beta1.NetworkNeighborhood
	CallCount            int
}

func (m *SpyProfileClient) ListNetworkNeighborhoods(namespace string, limit int64, cont string) (*v1beta1.NetworkNeighborhoodList, error) {
	m.CallCount++
	start := 0
	if cont != "" {
		fmt.Sscanf(cont, "%d", &start)
	}

	end := start + int(limit)
	nextCont := ""
	if end < len(m.NetworkNeighborhoods) {
		nextCont = fmt.Sprintf("%d", end)
	} else {
		end = len(m.NetworkNeighborhoods)
	}

	return &v1beta1.NetworkNeighborhoodList{
		ListMeta: metav1.ListMeta{
			Continue: nextCont,
		},
		Items: m.NetworkNeighborhoods[start:end],
	}, nil
}

func (m *SpyProfileClient) ListApplicationProfiles(namespace string, limit int64, cont string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}

func (m *SpyProfileClient) GetNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error) {
	// Return empty object
	return &v1beta1.NetworkNeighborhood{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"kubescape.io/completion": "complete",
				"kubescape.io/status":     "completed",
			},
		},
	}, nil
}

func TestPagination(t *testing.T) {
	totalItems := 120
	items := make([]v1beta1.NetworkNeighborhood, totalItems)
	for i := 0; i < totalItems; i++ {
		items[i] = v1beta1.NetworkNeighborhood{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("nn-%d", i),
				Namespace: "default",
				Annotations: map[string]string{
					"kubescape.io/completion": "complete",
					"kubescape.io/status":     "completed",
				},
				Labels: map[string]string{
					"kubescape.io/wlid-template-hash": "hash",
				},
			},
		}
	}

	spy := &SpyProfileClient{NetworkNeighborhoods: items}

	cache := NewNetworkNeighborhoodCache(config.Config{}, spy, nil)

	// Inject a container so that "default" namespace is processed.
	cache.containerIDToInfo.Set("test-container", &ContainerInfo{
		Namespace:  "default",
		WorkloadID: "wlid",
	})

	// Call the private method
	cache.updateAllNetworkNeighborhoods(context.Background())

	// We expect 3 calls:
	// 1. 0-50, returns continue="50"
	// 2. 50-100, returns continue="100"
	// 3. 100-120, returns continue=""
	if spy.CallCount != 3 {
		t.Errorf("Expected 3 calls to ListNetworkNeighborhoods, got %d", spy.CallCount)
	}
}
