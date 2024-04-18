package mocks

import (
	"os"
	"path"
	"runtime"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type TestKinds string
type TestName string

const (
	TestKindPod    TestKinds = "Pod"
	TestKindRS     TestKinds = "ReplicaSet"
	TestKindDeploy TestKinds = "Deployment"
	TestKindAP     TestKinds = "ApplicationProfile"
	TestKindAA     TestKinds = "ApplicationActivity"
	TestKindNN     TestKinds = "NetworkNeighborhood"
)

const (
	TestNginx      TestName = "nginx"
	TestCollection TestName = "collection"
)

const (
	nginxPodBytes                  = "testdata/nginx_pod.json"
	nginxRSBytes                   = "testdata/nginx_rs.json"
	nginxDeploymentBytes           = "testdata/nginx_deploy.json"
	nginxApplicationProfileBytes   = "testdata/nginx_applicationprofiles.json"
	nginxApplicationActivityBytes  = "testdata/nginx_applicationactivities.json"
	nginxNetworkNeighborhoodsBytes = "testdata/nginx_networkneighborhoods.json"
)
const (
	collectionPodBytes                  = "testdata/collection_pod.json"
	collectionRSBytes                   = "testdata/collection_rs.json"
	collectionDeploymentBytes           = "testdata/collection_deploy.json"
	collectionApplicationProfileBytes   = "testdata/collection_applicationprofiles.json"
	collectionApplicationActivityBytes  = "testdata/collection_applicationactivities.json"
	collectionNetworkNeighborhoodsBytes = "testdata/collection_networkneighborhoods.json"
)

var NAMESPACE = ""

func readFile(p string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	p = dir + "/mocks/" + p
	f, e := os.ReadFile(p)
	if e != nil {
		panic(e)
	}
	return f
}

func UnstructuredToRuntime(u *unstructured.Unstructured) k8sruntime.Object {
	if NAMESPACE != "" {
		u.SetNamespace(NAMESPACE)
	}
	if ns := os.Getenv("TEST_NAMESPACE"); ns != "" {
		u.SetNamespace(ns)
	}
	switch TestKinds(u.GetKind()) {
	case TestKindPod:
		pod := &corev1.Pod{}
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, pod); err == nil {
			return pod
		}
	case TestKindRS:
		rs := &appsv1.ReplicaSet{}
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, rs); err == nil {
			return rs
		}
	case TestKindDeploy:
		deploy := &appsv1.Deployment{}
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, deploy); err == nil {
			return deploy
		}
	case TestKindAP:
		ap := &v1beta1.ApplicationProfile{}
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, ap); err == nil {
			return ap
		}
	case TestKindAA:
		aa := &v1beta1.ApplicationActivity{}
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, aa); err == nil {
			return aa
		}
	case TestKindNN:
		nn := &v1beta1.NetworkNeighborhood{}
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, nn); err == nil {
			return nn
		}
	}
	return nil
}
func GetRuntime(kind TestKinds, name TestName) k8sruntime.Object {
	u := GetUnstructured(kind, name)

	// convert unstructured.Unstructured to a Node
	return UnstructuredToRuntime(u)
}
func GetUnstructured(kind TestKinds, name TestName) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	b := GetBytes(kind, name)
	if err := u.UnmarshalJSON(b); err != nil {
		panic(err)
	}
	if NAMESPACE != "" {
		u.SetNamespace(NAMESPACE)
	}
	if ns := os.Getenv("TEST_NAMESPACE"); ns != "" {
		u.SetNamespace(ns)
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
			return readFile(nginxNetworkNeighborhoodsBytes)
		case TestCollection:
			return readFile(collectionNetworkNeighborhoodsBytes)
		}
	}
	return []byte{}
}
