package storage

import (
	"context"
	"fmt"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

var seccompProfileCRDGVR = schema.GroupVersionResource{
	Group:    "kubescape.io",
	Version:  "v1",
	Resource: "seccompprofiles",
}

// CRDSeccompProfileClient implements SeccompProfileClient using the native CRD backend
type CRDSeccompProfileClient struct {
	dynamicClient dynamic.Interface
}

// NewCRDSeccompProfileClient creates a new CRD-backed SeccompProfile client
func NewCRDSeccompProfileClient(dynamicClient dynamic.Interface) *CRDSeccompProfileClient {
	return &CRDSeccompProfileClient{
		dynamicClient: dynamicClient,
	}
}

func (c *CRDSeccompProfileClient) WatchSeccompProfiles(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	w, err := c.dynamicClient.Resource(seccompProfileCRDGVR).Namespace(namespace).Watch(context.Background(), opts)
	if err != nil {
		return nil, err
	}
	// Wrap the watch to convert unstructured objects to typed SeccompProfile objects
	return newConvertingWatch(w), nil
}

func (c *CRDSeccompProfileClient) ListSeccompProfiles(namespace string, opts metav1.ListOptions) (*v1beta1.SeccompProfileList, error) {
	unstructuredList, err := c.dynamicClient.Resource(seccompProfileCRDGVR).Namespace(namespace).List(context.Background(), opts)
	if err != nil {
		return nil, err
	}

	result := &v1beta1.SeccompProfileList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SeccompProfileList",
			APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		},
	}

	// Set ListMeta from unstructured
	if metadata, ok := unstructuredList.Object["metadata"].(map[string]interface{}); ok {
		if rv, ok := metadata["resourceVersion"].(string); ok {
			result.ListMeta.ResourceVersion = rv
		}
		if cont, ok := metadata["continue"].(string); ok {
			result.ListMeta.Continue = cont
		}
	}

	result.Items = make([]v1beta1.SeccompProfile, 0, len(unstructuredList.Items))
	for _, item := range unstructuredList.Items {
		profile := &v1beta1.SeccompProfile{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, profile); err != nil {
			return nil, fmt.Errorf("failed to convert unstructured to SeccompProfile: %w", err)
		}
		result.Items = append(result.Items, *profile)
	}

	return result, nil
}

func (c *CRDSeccompProfileClient) GetSeccompProfile(namespace, name string) (*v1beta1.SeccompProfile, error) {
	unstructured, err := c.dynamicClient.Resource(seccompProfileCRDGVR).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	profile := &v1beta1.SeccompProfile{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructured.Object, profile); err != nil {
		return nil, fmt.Errorf("failed to convert unstructured to SeccompProfile: %w", err)
	}

	return profile, nil
}

// convertingWatch wraps a watch.Interface to convert unstructured objects to typed SeccompProfile objects
type convertingWatch struct {
	source  watch.Interface
	result  chan watch.Event
	stopped bool
}

func newConvertingWatch(source watch.Interface) *convertingWatch {
	cw := &convertingWatch{
		source: source,
		result: make(chan watch.Event),
	}
	go cw.run()
	return cw
}

func (cw *convertingWatch) run() {
	defer close(cw.result)
	for event := range cw.source.ResultChan() {
		if event.Type == watch.Error {
			cw.result <- event
			continue
		}

		if event.Object == nil {
			cw.result <- event
			continue
		}

		// Convert unstructured to typed SeccompProfile
		unstructuredObj, ok := event.Object.(runtime.Unstructured)
		if !ok {
			// If it's already typed, pass through
			cw.result <- event
			continue
		}

		profile := &v1beta1.SeccompProfile{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.UnstructuredContent(), profile); err != nil {
			// On conversion error, send an error event
			cw.result <- watch.Event{
				Type:   watch.Error,
				Object: event.Object,
			}
			continue
		}

		cw.result <- watch.Event{
			Type:   event.Type,
			Object: profile,
		}
	}
}

func (cw *convertingWatch) Stop() {
	cw.source.Stop()
	cw.stopped = true
}

func (cw *convertingWatch) ResultChan() <-chan watch.Event {
	return cw.result
}

