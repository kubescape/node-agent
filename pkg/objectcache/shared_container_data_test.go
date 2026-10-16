package objectcache

import (
	"sync"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeImageName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "nginx",
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "nginx:tag",
			want: "docker.io/library/nginx:tag",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeImageName(tt.name))
		})
	}
}

func Test_GetLabels(t *testing.T) {
	type args struct {
		watchedContainer *WatchedContainerData
		stripContainer   bool
	}
	instanceID, _ := instanceidhandler.GenerateInstanceIDFromString("apiVersion-v1/namespace-aaa/kind-Deployment/name-redis/containerName-redis")
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "TestGetLabels",
			args: args{
				watchedContainer: &WatchedContainerData{
					InstanceID: instanceID,
					Wlid:       "wlid://cluster-name/namespace-aaa/deployment-redis",
				},
			},
			want: map[string]string{
				"kubescape.io/workload-api-version":    "v1",
				"kubescape.io/workload-container-name": "redis",
				"kubescape.io/workload-kind":           "Deployment",
				"kubescape.io/learning-period":         "0s",
				"kubescape.io/workload-name":           "redis",
				"kubescape.io/workload-namespace":      "aaa",
			},
		},
		{
			name: "TestGetLabels",
			args: args{
				watchedContainer: &WatchedContainerData{
					InstanceID: instanceID,
					Wlid:       "wlid://cluster-name/namespace-aaa/deployment-redis",
				},
				stripContainer: true,
			},
			want: map[string]string{
				"kubescape.io/workload-api-version": "v1",
				"kubescape.io/workload-kind":        "Deployment",
				"kubescape.io/learning-period":      "0s",
				"kubescape.io/workload-name":        "redis",
				"kubescape.io/workload-namespace":   "aaa",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetLabels(nil, tt.args.watchedContainer, tt.args.stripContainer)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_formatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{
			d:    5 * time.Minute,
			want: "5m",
		},
		{
			d:    1*time.Hour + 30*time.Minute,
			want: "1h30m",
		},
		{
			d:    45 * time.Second,
			want: "45s",
		},
		{
			d:    1*time.Hour + 30*time.Second,
			want: "1h30s",
		},
		{
			d:    1 * time.Hour,
			want: "1h",
		},
	}
	for _, tt := range tests {
		t.Run(tt.d.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, formatDuration(tt.d))
		})
	}
}

func TestWatchedContainerData_StatusConcurrency(t *testing.T) {
	data := &WatchedContainerData{}
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			data.SetStatus(WatchedContainerStatusReady)
			_ = data.GetStatus()
		}()
		go func() {
			defer wg.Done()
			data.SetStatus(WatchedContainerStatusCompleted)
			_ = data.GetStatus()
		}()
		go func() {
			defer wg.Done()
			data.SetCompletionStatus(WatchedContainerCompletionStatusPartial)
			_ = data.GetCompletionStatus()
		}()
		go func() {
			defer wg.Done()
			data.SetCompletionStatus(WatchedContainerCompletionStatusFull)
			_ = data.GetCompletionStatus()
		}()
	}

	wg.Wait()
}

func TestWatchedContainerData_SetReadyUnlessTerminal(t *testing.T) {
	// Non-terminal states can transition to Ready
	data := &WatchedContainerData{}
	assert.False(t, data.IsTerminal())
	assert.True(t, data.SetReadyUnlessTerminal())
	assert.Equal(t, WatchedContainerStatusReady, data.GetStatus())

	data.SetStatus(WatchedContainerStatusInitializing)
	assert.False(t, data.IsTerminal())
	assert.True(t, data.SetReadyUnlessTerminal())
	assert.Equal(t, WatchedContainerStatusReady, data.GetStatus())

	// Terminal states cannot transition to Ready
	terminalStates := []WatchedContainerStatus{
		WatchedContainerStatusCompleted,
		WatchedContainerStatusFailed,
		WatchedContainerStatusMissingRuntime,
		WatchedContainerStatusTooLarge,
		WatchedContainerStatusRejected,
	}

	for _, state := range terminalStates {
		t.Run(string(state), func(t *testing.T) {
			assert.True(t, state.IsTerminal())
			data.SetStatus(state)
			assert.True(t, data.IsTerminal())
			assert.False(t, data.SetReadyUnlessTerminal())
			assert.Equal(t, state, data.GetStatus())
		})
	}
}

func TestWatchedContainerData_SetReadyUnlessTerminal_ConcurrentTermination(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		data := &WatchedContainerData{}
		data.SetStatus(WatchedContainerStatusReady)

		var wg sync.WaitGroup
		start := make(chan struct{})

		// Ticker simulator
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 50; i++ {
				data.SetReadyUnlessTerminal()
			}
		}()

		// Deletion simulator
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			data.SetStatus(WatchedContainerStatusCompleted)
		}()

		close(start)
		wg.Wait()

		// Once completed, it must not regress to Ready
		assert.Equal(t, WatchedContainerStatusCompleted, data.GetStatus())
	}
}
