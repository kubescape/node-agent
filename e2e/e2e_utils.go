package e2e

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func isPodRunning(k8sClient *kubernetes.Clientset, podName, namespace string) bool {
	// run request to Kubernetes apis
	pod, err := k8sClient.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app.kubernetes.io/name=%s", podName)},
	)
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

func waitForPod(k8sClient *kubernetes.Clientset, podName, namespace string, timeout int) error {
	result := make(chan bool, 1)
	for {
		result <- isPodRunning(k8sClient, podName, namespace)
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
				time.Sleep(2 * time.Second)
			}
		}
	}
}
