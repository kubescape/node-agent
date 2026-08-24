package nodeprofilemanager

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestConfig(url, method string, timeoutSeconds int) config.Config {
	return config.Config{
		NodeProfileInterval:    1 * time.Second,
		EnableRuntimeDetection: true,
		Exporters: exporters.ExportersConfig{
			HTTPExporterConfig: &exporters.HTTPExporterConfig{
				URL:            url,
				Method:         method,
				TimeoutSeconds: timeoutSeconds,
				Headers: []exporters.HTTPKeyValues{
					{Key: "Content-Type", Value: "application/json"},
				},
			},
		},
	}
}

func TestNewNodeProfileManager(t *testing.T) {
	t.Run("default timeout is 5 seconds", func(t *testing.T) {
		cfg := newTestConfig("http://localhost", "POST", 0)
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{},
			"test-node",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			nil,
		)
		assert.NotNil(t, npm)
		assert.Equal(t, 5*time.Second, npm.httpClient.Timeout)
	})

	t.Run("custom timeout from config", func(t *testing.T) {
		cfg := newTestConfig("http://localhost", "POST", 10)
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{},
			"test-node",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			nil,
		)
		assert.Equal(t, 10*time.Second, npm.httpClient.Timeout)
	})

	t.Run("cloud metadata is stored", func(t *testing.T) {
		cloudMeta := &armotypes.CloudMetadata{
			Provider: "aws",
		}
		cfg := newTestConfig("http://localhost", "POST", 0)
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{ClusterName: "test-cluster", AccountID: "test-account"},
			"node-1",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			cloudMeta,
		)
		assert.Equal(t, "node-1", npm.nodeName)
		assert.Equal(t, "test-cluster", npm.clusterData.ClusterName)
		assert.Equal(t, cloudMeta, npm.cloudMetadata)
	})
}

func TestGetContainerState(t *testing.T) {
	tests := []struct {
		name         string
		state        corev1.ContainerState
		wantState    string
		wantStarted  bool
		wantFinished bool
		wantExitCode int
	}{
		{
			name: "running container",
			state: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{
					StartedAt: metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
				},
			},
			wantState:   "Running",
			wantStarted: true,
		},
		{
			name: "terminated container",
			state: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   137,
					StartedAt:  metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
					FinishedAt: metav1.Time{Time: time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC)},
				},
			},
			wantState:    "Terminated",
			wantStarted:  true,
			wantFinished: true,
			wantExitCode: 137,
		},
		{
			name: "waiting container",
			state: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff",
				},
			},
			wantState: "Waiting",
		},
		{
			name:      "unknown state (all nil)",
			state:     corev1.ContainerState{},
			wantState: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, started, finished, exitCode := getContainerState(tt.state)
			assert.Equal(t, tt.wantState, state)
			if tt.wantStarted {
				assert.False(t, started.IsZero(), "expected non-zero start time")
			} else {
				assert.True(t, started.IsZero(), "expected zero start time")
			}
			if tt.wantFinished {
				assert.False(t, finished.IsZero(), "expected non-zero finish time")
			} else {
				assert.True(t, finished.IsZero(), "expected zero finish time")
			}
			assert.Equal(t, tt.wantExitCode, exitCode)
		})
	}
}

func TestGetPodState(t *testing.T) {
	tests := []struct {
		name           string
		conditions     []corev1.PodCondition
		wantState      string
		wantReason     string
		wantMessage    string
		wantHasTransit bool
	}{
		{
			name:       "no conditions returns empty",
			conditions: nil,
			wantState:  "",
		},
		{
			name: "PodReady true returns state",
			conditions: []corev1.PodCondition{
				{
					Type:               corev1.PodReady,
					Status:             corev1.ConditionTrue,
					Reason:             "PodReady",
					Message:            "All containers ready",
					LastTransitionTime: metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
				},
			},
			wantState:      "Ready",
			wantReason:     "PodReady",
			wantMessage:    "All containers ready",
			wantHasTransit: true,
		},
		{
			name: "PodReady false is skipped",
			conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionFalse,
					Reason: "ContainersNotReady",
				},
			},
			wantState: "",
		},
		{
			name: "multiple conditions returns first Ready=True",
			conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodScheduled,
					Status: corev1.ConditionTrue,
				},
				{
					Type:               corev1.PodReady,
					Status:             corev1.ConditionTrue,
					Reason:             "Ready",
					LastTransitionTime: metav1.Time{Time: time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)},
				},
			},
			wantState:      "Ready",
			wantReason:     "Ready",
			wantHasTransit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, reason, message, transitionTime := getPodState(tt.conditions)
			assert.Equal(t, tt.wantState, state)
			assert.Equal(t, tt.wantReason, reason)
			assert.Equal(t, tt.wantMessage, message)
			if tt.wantHasTransit {
				assert.False(t, transitionTime.IsZero())
			} else {
				assert.True(t, transitionTime.IsZero())
			}
		})
	}
}

func TestGetProfile(t *testing.T) {
	cloudMeta := &armotypes.CloudMetadata{Provider: "gcp"}

	k8sCache := &objectcache.K8sObjectCacheMock{
		PodSpec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx:latest"},
				{Name: "sidecar", Image: "envoy:v1"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "busybox:latest"},
			},
		},
		PodStatus: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{
					Type:               corev1.PodReady,
					Status:             corev1.ConditionTrue,
					LastTransitionTime: metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
				},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "app",
					RestartCount: 2,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
						},
					},
				},
				{
					Name: "sidecar",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"},
					},
				},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "init",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
					},
				},
			},
		},
	}

	cfg := newTestConfig("http://localhost", "POST", 5)
	cfg.EnableRuntimeDetection = true

	npm := NewNodeProfileManager(
		cfg,
		armometadata.ClusterConfig{AccountID: "acc-123", ClusterName: "cluster-1"},
		"node-1",
		k8sCache,
		rulemanager.CreateRuleManagerMock(),
		cloudMeta,
	)

	profile, err := npm.getProfile()
	require.NoError(t, err)
	assert.NotNil(t, profile)
	assert.Equal(t, "Running", profile.CurrentState)
	assert.True(t, profile.NodeAgentRunning)
	assert.True(t, profile.RuntimeDetectionEnabled)
	assert.Equal(t, cloudMeta, profile.CloudMetadata)
	assert.Len(t, profile.PodStatuses, 1)

	ps := profile.PodStatuses[0]
	assert.Equal(t, "acc-123", ps.CustomerGUID)
	assert.Equal(t, "cluster-1", ps.Cluster)
	assert.Equal(t, "node-1", ps.NodeName)
	assert.Equal(t, string(corev1.PodRunning), ps.Phase)

	assert.Len(t, ps.Containers, 2)
	assert.Equal(t, "app", ps.Containers[0].Name)
	assert.Equal(t, "nginx:latest", ps.Containers[0].Image)
	assert.Equal(t, "Running", ps.Containers[0].CurrentState)
	assert.Equal(t, 2, ps.Containers[0].RestartCount)

	assert.Equal(t, "sidecar", ps.Containers[1].Name)
	assert.Equal(t, "Waiting", ps.Containers[1].CurrentState)

	assert.Len(t, ps.InitContainers, 1)
	assert.Equal(t, "init", ps.InitContainers[0].Name)
	assert.Equal(t, "Terminated", ps.InitContainers[0].CurrentState)
	assert.Equal(t, 0, ps.InitContainers[0].LastStateExitCode)
}

type localK8sCache struct {
	objectcache.K8sObjectCacheMock
	pods []*corev1.Pod
}

func (c *localK8sCache) GetPods() []*corev1.Pod {
	return c.pods
}

func TestGetProfile_AppLabel(t *testing.T) {
	tests := []struct {
		name      string
		labels    map[string]string
		expectApp string
	}{
		{
			name:      "app label present",
			labels:    map[string]string{"app": "myapp"},
			expectApp: "myapp",
		},
		{
			name:      "app.kubernetes.io/name present",
			labels:    map[string]string{"app.kubernetes.io/name": "myapp2"},
			expectApp: "myapp2",
		},
		{
			name:      "app takes precedence over app.kubernetes.io/name",
			labels:    map[string]string{"app": "first", "app.kubernetes.io/name": "second"},
			expectApp: "first",
		},
		{
			name:      "no app labels",
			labels:    map[string]string{"version": "v1"},
			expectApp: "",
		},
		{
			name:      "nil labels",
			labels:    nil,
			expectApp: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sCache := &localK8sCache{
				pods: []*corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-pod",
							Namespace: "default",
							Labels:    tt.labels,
						},
					},
				},
			}
			cfg := newTestConfig("http://localhost", "POST", 5)
			npm := NewNodeProfileManager(
				cfg,
				armometadata.ClusterConfig{},
				"node-1",
				k8sCache,
				rulemanager.CreateRuleManagerMock(),
				nil,
			)

			profile, err := npm.getProfile()
			require.NoError(t, err)
			require.Len(t, profile.PodStatuses, 1)
			assert.Equal(t, tt.expectApp, profile.PodStatuses[0].App)
		})
	}
}

func TestSendProfile(t *testing.T) {
	t.Run("successful send", func(t *testing.T) {
		var receivedBody []byte
		var receivedContentType string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedContentType = r.Header.Get("Content-Type")
			var err error
			receivedBody, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := newTestConfig(server.URL, "POST", 5)
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{},
			"test-node",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			nil,
		)

		profile := &armotypes.NodeProfile{
			CurrentState:     "Running",
			NodeAgentRunning: true,
			PodStatuses:      []armotypes.PodStatus{},
		}

		err := npm.sendProfile(profile)
		assert.NoError(t, err)
		assert.Equal(t, "application/json", receivedContentType)

		var crd armotypes.GenericCRD[armotypes.NodeProfile]
		err = json.Unmarshal(receivedBody, &crd)
		require.NoError(t, err)
		assert.Equal(t, "NodeProfiles", crd.Kind)
		assert.Equal(t, "kubescape.io/v1", crd.ApiVersion)
		assert.Equal(t, "test-node", crd.Metadata.Name)
		assert.Equal(t, "Running", crd.Spec.CurrentState)
		assert.True(t, crd.Spec.NodeAgentRunning)
	})

	t.Run("non-2xx status code returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		cfg := newTestConfig(server.URL, "POST", 5)
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{},
			"test-node",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			nil,
		)

		err := npm.sendProfile(&armotypes.NodeProfile{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-2xx status code: 500")
	})

	t.Run("connection error returns error", func(t *testing.T) {
		cfg := newTestConfig("http://127.0.0.1:1", "POST", 1)
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{},
			"test-node",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			nil,
		)

		err := npm.sendProfile(&armotypes.NodeProfile{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "send request")
	})

	t.Run("custom headers are sent", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			receivedHeaders = r.Header
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := newTestConfig(server.URL, "PUT", 5)
		cfg.Exporters.HTTPExporterConfig.Headers = []exporters.HTTPKeyValues{
			{Key: "Content-Type", Value: "application/json"},
			{Key: "X-Custom-Header", Value: "test-value"},
		}
		npm := NewNodeProfileManager(
			cfg,
			armometadata.ClusterConfig{},
			"test-node",
			&objectcache.K8sObjectCacheMock{},
			rulemanager.CreateRuleManagerMock(),
			nil,
		)

		err := npm.sendProfile(&armotypes.NodeProfile{})
		assert.NoError(t, err)
		assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
		assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
	})
}

func TestGetContainers(t *testing.T) {
	cfg := newTestConfig("http://localhost", "POST", 5)
	npm := NewNodeProfileManager(
		cfg,
		armometadata.ClusterConfig{},
		"test-node",
		&objectcache.K8sObjectCacheMock{},
		rulemanager.CreateRuleManagerMock(),
		nil,
	)

	t.Run("empty containers returns empty slice", func(t *testing.T) {
		result := npm.getContainers("ns", "pod", nil, nil)
		assert.Nil(t, result)
	})

	t.Run("containers with matching statuses", func(t *testing.T) {
		containers := []corev1.Container{
			{Name: "web", Image: "nginx:1.25"},
			{Name: "log", Image: "fluentd:v1"},
		}
		statuses := map[string]corev1.ContainerStatus{
			"web": {
				Name:         "web",
				RestartCount: 3,
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{
						StartedAt: metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
					},
				},
			},
		}

		result := npm.getContainers("default", "test-pod", containers, statuses)
		assert.Len(t, result, 2)
		assert.Equal(t, "web", result[0].Name)
		assert.Equal(t, "nginx:1.25", result[0].Image)
		assert.Equal(t, "Running", result[0].CurrentState)
		assert.Equal(t, 3, result[0].RestartCount)
		assert.Equal(t, "log", result[1].Name)
		assert.Equal(t, "Unknown", result[1].CurrentState)
	})
}

func TestGetEphemeralContainers(t *testing.T) {
	cfg := newTestConfig("http://localhost", "POST", 5)
	npm := NewNodeProfileManager(
		cfg,
		armometadata.ClusterConfig{},
		"test-node",
		&objectcache.K8sObjectCacheMock{},
		rulemanager.CreateRuleManagerMock(),
		nil,
	)

	t.Run("ephemeral containers", func(t *testing.T) {
		containers := []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  "debug",
					Image: "busybox:latest",
				},
			},
		}
		statuses := map[string]corev1.ContainerStatus{
			"debug": {
				Name: "debug",
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{},
				},
			},
		}

		result := npm.getEphemeralContainers("default", "pod", containers, statuses)
		assert.Len(t, result, 1)
		assert.Equal(t, "debug", result[0].Name)
		assert.Equal(t, "busybox:latest", result[0].Image)
		assert.Equal(t, "Running", result[0].CurrentState)
	})

	t.Run("empty ephemeral containers", func(t *testing.T) {
		result := npm.getEphemeralContainers("default", "pod", nil, nil)
		assert.Nil(t, result)
	})
}
