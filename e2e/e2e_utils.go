package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func isPodRunning(k8sClient *kubernetes.Clientset, podName, namespace, label string) bool {
	// run request to Kubernetes apis
	pod, err := k8sClient.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		return false
	}
	// if items are more than 1 then we are not selecting pods in the right way
	if len(pod.Items) > 1 {
		return false
	}

	switch pod.Items[0].Status.Phase {
	case v1.PodRunning:
		return true
	default:
		return false
	}
}

func waitForPod(k8sClient *kubernetes.Clientset, podName, namespace, label string, timeout int) error {
	result := make(chan bool, 1)
	for {
		result <- isPodRunning(k8sClient, podName, namespace, label)
		select {
		// time out was reached
		case <-time.After(time.Duration(timeout) * time.Second):
			return fmt.Errorf("timed out")
		// check result retrieved from function
		case res := <-result:
			switch res {
			case true:
				return nil
			case false:
				fmt.Printf("pod: %s not ready yet\n", podName)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func createPod(k8sClient *kubernetes.Clientset, pod *v1.Pod) (*v1.Pod, error) {
	data, err := k8sClient.CoreV1().
		Pods("default").
		Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("error creating Pod: %v", err)
	}
	return data, nil
}

func deletePod(k8sClient *kubernetes.Clientset, pod *v1.Pod) error {
	err := k8sClient.CoreV1().
		Pods("default").
		Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error creating Pod: %v", err)
	}
	return nil
}

func createCustomResource(k8sClient *kubernetes.Clientset, path string, body interface{}) ([]byte, error) {
	data, err := k8sClient.CoreV1().
		RESTClient().
		Post().
		AbsPath(path).
		Body(body).
		DoRaw(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("error creating CustomResource: %v", err)
	}
	return data, nil
}

func getCustomResourceData(k8sClient *kubernetes.Clientset, path string) ([]byte, error) {
	return k8sClient.RESTClient().
		Get().
		AbsPath(path).
		DoRaw(context.TODO())
}

func deleteCustomResourceData(k8sClient *kubernetes.Clientset, path string) ([]byte, error) {
	return k8sClient.RESTClient().
		Delete().
		AbsPath(path).
		DoRaw(context.TODO())
}

func getCustomResource(k8sClient *kubernetes.Clientset, path string) ([]byte, error) {
	data, err := getCustomResourceData(k8sClient, path)
	if err != nil {
		return nil, fmt.Errorf("error getting CustomResource: %v", err)
	}
	return data, nil
}

func isCustomResourceExists(k8sClient *kubernetes.Clientset, path string) bool {
	data, err := getCustomResourceData(k8sClient, path)
	if err != nil {
		return false
	}
	type Response struct {
		Kind       string                   `json:"kind"`
		ApiVersion string                   `json:"apiVersion"`
		Metadata   map[string]string        `json:"metadata"`
		Items      []map[string]interface{} `json:"items"`
	}
	var response Response
	err = json.Unmarshal(data, &response)
	if err != nil {
		return false
	}
	if len(response.Items) == 0 {
		return false
	}
	return true
}

func waitForCustomResource(k8sClient *kubernetes.Clientset, path string, timeout int) error {
	result := make(chan bool, 1)
	for {
		result <- isCustomResourceExists(k8sClient, path)
		select {
		// time out was reached
		case <-time.After(time.Duration(timeout) * time.Second):
			return fmt.Errorf("timed out")
		// check result retrieved from function
		case res := <-result:
			switch res {
			case true:
				return nil
			case false:
				fmt.Printf("resource: %s not ready yet\n", path)
				time.Sleep(10 * time.Second)
			}
		}
	}
}
