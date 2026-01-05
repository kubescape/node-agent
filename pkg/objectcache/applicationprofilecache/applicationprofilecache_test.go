package applicationprofilecache

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
	Profiles  []v1beta1.ApplicationProfile
	CallCount int
}

func (m *SpyProfileClient) ListApplicationProfiles(namespace string, limit int64, cont string) (*v1beta1.ApplicationProfileList, error) {
	m.CallCount++
	start := 0
	if cont != "" {
		fmt.Sscanf(cont, "%d", &start)
	}

	end := start + int(limit)
	nextCont := ""
	if end < len(m.Profiles) {
		nextCont = fmt.Sprintf("%d", end)
	} else {
		end = len(m.Profiles)
	}

	return &v1beta1.ApplicationProfileList{
		ListMeta: metav1.ListMeta{
			Continue: nextCont,
		},
		Items: m.Profiles[start:end],
	}, nil
}

func (m *SpyProfileClient) GetApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error) {
	// Return empty profile to avoid errors in update loop
	return &v1beta1.ApplicationProfile{
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
	totalProfiles := 120
	profiles := make([]v1beta1.ApplicationProfile, totalProfiles)
	for i := 0; i < totalProfiles; i++ {
		profiles[i] = v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("profile-%d", i),
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

	spy := &SpyProfileClient{Profiles: profiles}

	// mock k8s object cache is irrelevant since we inject container info directly
	cache := NewApplicationProfileCache(config.Config{}, spy, nil)

	// Inject a container so that "default" namespace is processed.
	// The WorkloadID needs to match something if we want deeper logic to run,
	// but for pagination of ListApplicationProfiles, we just need to get past `getContainerIDsForNamespace` check.
	// AND we need to simulate at least one container to trigger the list call.
	cache.containerIDToInfo.Set("test-container", &ContainerInfo{
		Namespace:  "default",
		WorkloadID: "wlid",
	})

	// Call the private method
	cache.updateAllProfiles(context.Background())

	// We expect 3 calls:
	// 1. 0-50, returns continue="50"
	// 2. 50-100, returns continue="100"
	// 3. 100-120, returns continue=""
	// (Implementation loop checks continueToken == "")

	if spy.CallCount != 3 {
		t.Errorf("Expected 3 calls to ListApplicationProfiles, got %d", spy.CallCount)
	}
}
