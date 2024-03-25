package objectcache

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type TestKinds string

const (
	TestKindPod    TestKinds = "Pod"
	TestKindRS     TestKinds = "ReplicaSet"
	TestKindDeploy TestKinds = "Deployment"
	TestKindAP     TestKinds = "ApplicationProfile"
	TestKindAA     TestKinds = "ApplicationActivity"
	TestKindNN     TestKinds = "NetworkNeighbors"
)

type TestName string

const (
	TestNginx     TestName = "nginx"
	TestCollector TestName = "collector"
)

// go:embed testdata/nginx_pod.json
var nginxPodBytes []byte

// go:embed testdata/nginx_rs.json
var nginxRSBytes []byte

// go:embed testdata/nginx_deployment.json
var nginxDeploymentBytes []byte

// go:embed testdata/collector_pod.json
var collectorPodBytes []byte

// go:embed testdata/collector_rs.json
var collectorRSBytes []byte

// go:embed testdata/collector_deployment.json
var collectorDeploymentBytes []byte

// go:embed testdata/collection_applicationprofiles.json
var collectorApplicationProfileBytes []byte

// go:embed testdata/collection_applicationactivities.json
var collectorApplicationActivityBytes []byte

// go:embed testdata/collection_networkneighbors.json
var collectorNetworkNeighborsBytes []byte

// go:embed testdata/nginx_applicationprofiles.json
var nginxApplicationProfileBytes []byte

// go:embed testdata/nginx_applicationactivities.json
var nginxApplicationActivityBytes []byte

// go:embed testdata/nginx_networkneighbors.json
var nginxNetworkNeighborsBytes []byte

func GetPod(name TestName) *corev1.Pod {
	var pod *corev1.Pod
	switch name {
	case TestNginx:
		json.Unmarshal(nginxPodBytes, pod)
	case TestCollector:
		json.Unmarshal(collectorPodBytes, pod)
	}
	return pod
}

func GetUnstructured(kind TestKinds, name TestName) (*unstructured.Unstructured, error) {
	var u *unstructured.Unstructured
	b := GetBytes(kind, name)
	if err := json.Unmarshal(b, u); err != nil {
		return nil, err
	}

	return u, nil
}

func GetBytes(kind TestKinds, name TestName) []byte {
	switch kind {
	case TestKindPod:
		switch name {
		case TestNginx:
			return nginxPodBytes
		case TestCollector:
			return collectorPodBytes
		}
	case TestKindRS:
		switch name {
		case TestNginx:
			return nginxRSBytes
		case TestCollector:
			return collectorRSBytes
		}
	case TestKindDeploy:
		switch name {
		case TestNginx:
			return nginxDeploymentBytes
		case TestCollector:
			return collectorDeploymentBytes
		}
	case TestKindAA:
		switch name {
		case TestNginx:
			return nginxApplicationActivityBytes
		case TestCollector:
			return collectorApplicationActivityBytes
		}
	case TestKindAP:
		switch name {
		case TestNginx:
			return nginxApplicationProfileBytes
		case TestCollector:
			return collectorApplicationProfileBytes
		}
	case TestKindNN:
		switch name {
		case TestNginx:
			return nginxNetworkNeighborsBytes
		case TestCollector:
			return collectorNetworkNeighborsBytes
		}
	}
	return []byte{}
}

func TestUnstructuredToPod(t *testing.T) {

	tests := []struct {
		name TestName
		kind TestKinds
	}{
		{
			name: TestNginx,
			kind: TestKindPod,
		},
		{
			name: TestNginx,
			kind: TestKindRS,
		},
		{
			name: TestNginx,
			kind: TestKindDeploy,
		},
		{
			name: TestNginx,
			kind: TestKindAA,
		},
		{
			name: TestNginx,
			kind: TestKindAP,
		},
		{
			name: TestNginx,
			kind: TestKindNN,
		},

		{
			name: TestCollector,
			kind: TestKindPod,
		},
		{
			name: TestCollector,
			kind: TestKindRS,
		},
		{
			name: TestCollector,
			kind: TestKindDeploy,
		},
		{
			name: TestCollector,
			kind: TestKindAA,
		},
		{
			name: TestCollector,
			kind: TestKindAP,
		},
		{
			name: TestCollector,
			kind: TestKindNN,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.name, tt.kind), func(t *testing.T) {
			_, err := GetUnstructured(tt.kind, tt.name)
			assert.NoError(t, err)
		})
	}
}
