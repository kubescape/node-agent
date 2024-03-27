package objectcache

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
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
	TestNginx      TestName = "nginx"
	TestCollection TestName = "collection"
)

const (
	nginxPodBytes                 = "testdata/nginx_pod.json"
	nginxRSBytes                  = "testdata/nginx_rs.json"
	nginxDeploymentBytes          = "testdata/nginx_deploy.json"
	nginxApplicationProfileBytes  = "testdata/nginx_applicationprofiles.json"
	nginxApplicationActivityBytes = "testdata/nginx_applicationactivities.json"
	nginxNetworkNeighborsBytes    = "testdata/nginx_networkneighbors.json"
)
const (
	collectionPodBytes                 = "testdata/collection_pod.json"
	collectionRSBytes                  = "testdata/collection_rs.json"
	collectionDeploymentBytes          = "testdata/collection_deploy.json"
	collectionApplicationProfileBytes  = "testdata/collection_applicationprofiles.json"
	collectionApplicationActivityBytes = "testdata/collection_applicationactivities.json"
	collectionNetworkNeighborsBytes    = "testdata/collection_networkneighbors.json"
)

func readFile(p string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	p = dir + "/objectcache/" + p
	f, e := os.ReadFile(p)
	if e != nil {
		panic(e)
	}
	return f
}
func GetUnstructured(kind TestKinds, name TestName) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	b := GetBytes(kind, name)
	if err := u.UnmarshalJSON(b); err != nil {
		panic(err)
	}

	return u
}

func GetBytes(kind TestKinds, name TestName) []byte {
	switch kind {
	case TestKindPod:
		switch name {
		case TestNginx:
			return readFile(nginxPodBytes)
		case TestCollection:
			return readFile(collectionPodBytes)
		}
	case TestKindRS:
		switch name {
		case TestNginx:
			return readFile(nginxRSBytes)
		case TestCollection:
			return readFile(collectionRSBytes)
		}
	case TestKindDeploy:
		switch name {
		case TestNginx:
			return readFile(nginxDeploymentBytes)
		case TestCollection:
			return readFile(collectionDeploymentBytes)
		}
	case TestKindAA:
		switch name {
		case TestNginx:
			return readFile(nginxApplicationActivityBytes)
		case TestCollection:
			return readFile(collectionApplicationActivityBytes)
		}
	case TestKindAP:
		switch name {
		case TestNginx:
			return readFile(nginxApplicationProfileBytes)
		case TestCollection:
			return readFile(collectionApplicationProfileBytes)
		}
	case TestKindNN:
		switch name {
		case TestNginx:
			return readFile(nginxNetworkNeighborsBytes)
		case TestCollection:
			return readFile(collectionNetworkNeighborsBytes)
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
			name: TestCollection,
			kind: TestKindPod,
		},
		{
			name: TestCollection,
			kind: TestKindRS,
		},
		{
			name: TestCollection,
			kind: TestKindDeploy,
		},
		{
			name: TestCollection,
			kind: TestKindAA,
		},
		{
			name: TestCollection,
			kind: TestKindAP,
		},
		{
			name: TestCollection,
			kind: TestKindNN,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.name, tt.kind), func(t *testing.T) {
			u := GetUnstructured(tt.kind, tt.name)
			assert.NotNil(t, u)
		})
	}
}
