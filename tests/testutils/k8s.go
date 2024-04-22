package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"sigs.k8s.io/yaml"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1client "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

type TestWorkload struct {
	Namespace       string
	UnstructuredObj *unstructured.Unstructured
	WorkloadObj     *workloadinterface.Workload
	client          dynamic.ResourceInterface
}

func NewTestWorkload(namespace, resourcePath string) (*TestWorkload, error) {
	k8sClient := k8sinterface.NewKubernetesApi()

	yamlData, err := os.ReadFile(resourcePath)
	if err != nil {
		return nil, err
	}
	data, err := yaml.YAMLToJSON(yamlData)
	if err != nil {
		return nil, err
	}
	wl, err := workloadinterface.NewWorkload(data)
	if err != nil {
		return nil, err
	}

	gvr, err := k8sinterface.GetGroupVersionResource(wl.GetKind())
	if err != nil {
		return nil, err
	}

	clientResource := k8sClient.DynamicClient.Resource(gvr)

	obj := &unstructured.Unstructured{}
	err = obj.UnmarshalJSON(data)
	if err != nil {
		return nil, err
	}
	client := clientResource.Namespace(namespace)
	_, err = client.Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return &TestWorkload{
		Namespace:       namespace,
		UnstructuredObj: obj,
		WorkloadObj:     wl,
		client:          client,
	}, nil
}

func (w *TestWorkload) ExecIntoPod(command []string, container string) (string, string, error) {
	pods, err := w.GetPods()
	if err != nil {
		return "", "", err
	}
	pod := pods[0]

	k8sClient := k8sinterface.NewKubernetesApi()

	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}

	podExecOpts := &v1.PodExecOptions{
		Command: command,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}

	if container != "" {
		podExecOpts.Container = container
	}

	request := k8sClient.KubernetesClient.CoreV1().RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(podExecOpts, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(k8sClient.K8SConfig, "POST", request.URL())
	if err != nil {
		return "", "", err
	}
	err = exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	})
	if err != nil {
		return "", "", fmt.Errorf("%w Failed executing command %s on %v/%v", err, command, pod.Namespace, pod.Name)
	}

	return buf.String(), errBuf.String(), nil
}

func (w *TestWorkload) GetPods() ([]v1.Pod, error) {
	k8sClient := k8sinterface.NewKubernetesApi()

	appLabel, _ := w.WorkloadObj.GetLabel("app")
	namespace := w.Namespace

	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": appLabel}}
	listOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
	}

	pods, err := k8sClient.KubernetesClient.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pods found")
	}
	return pods.Items, nil
}

func (w *TestWorkload) WaitForReady(maxRetries uint64) error {
	time.Sleep(5 * time.Second)
	k8sClient := k8sinterface.NewKubernetesApi()

	pods, err := w.GetPods()
	if err != nil {
		return err
	}
	podNames := make([]string, 0)
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
	}

	for _, podName := range podNames {
		err := backoff.RetryNotify(func() error {
			p, err := k8sClient.KubernetesClient.CoreV1().Pods(w.Namespace).Get(context.TODO(), podName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			for _, cond := range p.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == "True" {
					return nil
				}
			}
			return fmt.Errorf("pod %s is not ready", podName)
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(5*time.Second), maxRetries), func(err error, d time.Duration) {
			logger.L().Info("waiting for pod to be ready", helpers.String("pod", podName), helpers.Error(err), helpers.String("retry in", d.String()))
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *TestWorkload) listApplicationProfilesInNamespace() ([]v1beta1.ApplicationProfile, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	profiles, err := storageclient.ApplicationProfiles(w.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return profiles.Items, nil
}

func (w *TestWorkload) listNetworkNeighborhoodInNamespace() ([]v1beta1.NetworkNeighborhood, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	profiles, err := storageclient.NetworkNeighborhoods(w.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return profiles.Items, nil
}

func (w *TestWorkload) getApplicationProfile() (*v1beta1.ApplicationProfile, error) {
	appProfiles, err := w.listApplicationProfilesInNamespace()
	if err != nil {
		return nil, err
	}

	for _, appProfile := range appProfiles {
		wlKind := appProfile.Labels["kubescape.io/workload-kind"]
		wlName := appProfile.Labels["kubescape.io/workload-name"]
		wlNs := appProfile.Labels["kubescape.io/workload-namespace"]

		if wlKind == w.WorkloadObj.GetKind() && wlName == w.WorkloadObj.GetName() && wlNs == w.Namespace {
			return &appProfile, nil
		}
	}
	return nil, fmt.Errorf("application profile not found")
}

func (w *TestWorkload) GetNetworkNeighborhood() (*v1beta1.NetworkNeighborhood, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	nn, err := w.listNetworkNeighborhoodInNamespace()
	if err != nil {
		return nil, err
	}

	for _, n := range nn {
		wlKind := n.Labels["kubescape.io/workload-kind"]
		wlName := n.Labels["kubescape.io/workload-name"]
		wlNs := n.Labels["kubescape.io/workload-namespace"]

		if wlKind == w.WorkloadObj.GetKind() && wlName == w.WorkloadObj.GetName() && wlNs == w.Namespace {
			// get the network neighborhood
			return storageclient.NetworkNeighborhoods(w.Namespace).Get(context.TODO(), n.Name, metav1.GetOptions{})
		}
	}
	return nil, fmt.Errorf("network neighborhood not found")
}

func (w *TestWorkload) WaitForApplicationProfileCompletion(maxRetries uint64) error {
	return w.WaitForApplicationProfile(maxRetries, "completed")
}

func (w *TestWorkload) WaitForApplicationProfile(maxRetries uint64, expectedStatus string) error {
	return backoff.RetryNotify(func() error {
		appProfile, err := w.getApplicationProfile()
		if err != nil {
			return err
		}

		if appProfile.Annotations["kubescape.io/status"] == expectedStatus {
			return nil
		}
		return fmt.Errorf("application profile is not in status '%s'", expectedStatus)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Second), maxRetries), func(err error, d time.Duration) {
		logger.L().Info("waiting for app profile", helpers.Error(err), helpers.String("retry in", d.String()))
	})
}

func (w *TestWorkload) WaitForNetworkNeighborhoodCompletion(maxRetries uint64) error {
	return w.WaitForNetworkNeighborhood(maxRetries, "completed")
}

func (w *TestWorkload) WaitForNetworkNeighborhood(maxRetries uint64, expectedStatus string) error {
	return backoff.RetryNotify(func() error {
		networkNeighborhood, err := w.GetNetworkNeighborhood()
		if err != nil {
			return err
		}

		if networkNeighborhood.Annotations["kubescape.io/status"] == expectedStatus {
			return nil
		}
		return fmt.Errorf("network neighborhood is not in status '%s'", expectedStatus)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Second), maxRetries), func(err error, d time.Duration) {
		logger.L().Info("waiting for network neighborhood", helpers.Error(err), helpers.String("retry in", d.String()))
	})
}

type TestNamespace struct {
	Name    string
	created bool
}

func NewRandomNamespace() TestNamespace {
	return NewNamespace(generateRandomNamespaceName())
}
func NewNamespace(name string) TestNamespace {
	ns := TestNamespace{}
	ns.Name = name

	k8sClient := k8sinterface.NewKubernetesApi()
	_, err := k8sClient.KubernetesClient.CoreV1().Namespaces().Get(context.TODO(), ns.Name, metav1.GetOptions{})
	if err != nil {
		nsSpec := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns.Name,
			},
		}

		_, err := k8sClient.KubernetesClient.CoreV1().Namespaces().Create(context.TODO(), nsSpec, metav1.CreateOptions{})
		if err != nil {
			panic(err)
		}
		ns.created = true

	} else {
		ns.created = false
	}

	return ns
}

func generateRandomNamespaceName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	var sb strings.Builder
	prefix := "node-agent-test-"
	sb.WriteString(prefix)
	for i := 0; i < 4; i++ {
		randomIndex := rand.Intn(len(letters))
		sb.WriteByte(letters[randomIndex])
	}
	return sb.String()
}

func CreateWorkloadsInPath(namespace, dir string) ([]TestWorkload, error) {
	workloads := []TestWorkload{}
	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			wl, err := NewTestWorkload(namespace, path)
			if err != nil {
				return err
			}
			workloads = append(workloads, *wl)
		}
		return nil
	})

	return workloads, err
}

func IncreaseNodeAgentSniffingTime(newDuration string) {
	k8sClient := k8sinterface.NewKubernetesApi()
	ctx := context.TODO()
	namespace := "kubescape"

	cm, err := k8sClient.KubernetesClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), "node-agent", metav1.GetOptions{})
	if err != nil {
		panic(err)
	}
	val := cm.Data["config.json"]
	config := map[string]interface{}{}
	err = json.Unmarshal([]byte(val), &config)
	if err != nil {
		panic(err)
	}
	config["maxSniffingTimePerContainer"] = newDuration

	newVal, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	cm.Data["config.json"] = string(newVal)
	_, err = k8sClient.KubernetesClient.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cm, metav1.UpdateOptions{})
	if err != nil {
		panic(err)
	}

	// restart the daemonset
	daemonset, err := k8sClient.KubernetesClient.AppsV1().DaemonSets(namespace).Get(context.TODO(), "node-agent", metav1.GetOptions{})
	if err != nil {
		panic(err)
	}

	if daemonset.Spec.Template.ObjectMeta.Annotations == nil {
		daemonset.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}
	daemonset.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

	_, err = k8sClient.KubernetesClient.AppsV1().DaemonSets(namespace).Update(ctx, daemonset, metav1.UpdateOptions{})
	if err != nil {
		panic(err)
	}

	time.Sleep(5 * time.Second)

	// wait for the daemonset to be ready
	err = backoff.RetryNotify(func() error {
		labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "node-agent"}}
		pods, err := k8sClient.KubernetesClient.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
		})
		if err != nil {
			return err
		}

		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods found")
		}

		for _, p := range pods.Items {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.Ready && cs.State.Running != nil {
					continue
				} else {
					return fmt.Errorf("pod %s is not ready", p.Name)
				}
			}
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Second), 40), func(err error, d time.Duration) {
		logger.L().Info("waiting for node agent", helpers.Error(err), helpers.String("retry in", d.String()))
	})
	if err != nil {
		panic(err)
	}

}

func AssertNetworkNeighborhoodNotContains(t *testing.T, nn *v1beta1.NetworkNeighborhood, containerName string, notExpectedEgress, notExpectedIngress []string) {
	container, err := getContainerFromNetworkNeighborhood(nn, containerName)
	if err != nil {
		t.Errorf("Error getting container from network neighborhood: %v", err)
		return
	}

	egress := getEgressDnsNames(container)
	for _, dnsName := range notExpectedEgress {
		assert.False(t, egress.Contains(dnsName), "did not expect egress DNS name '%s' in network neighborhood", dnsName)
	}
	ingress := getIngressDnsNames(container)
	for _, dnsName := range notExpectedIngress {
		assert.False(t, ingress.Contains(dnsName), "did not expect ingress DNS name '%s' in network neighborhood", dnsName)
	}
}

func AssertNetworkNeighborhoodContains(t *testing.T, nn *v1beta1.NetworkNeighborhood, containerName string, expectedEgress, expectedIngress []string) {
	container, err := getContainerFromNetworkNeighborhood(nn, containerName)
	if err != nil {
		t.Errorf("Error getting container from network neighborhood: %v", err)
		return
	}

	egress := getEgressDnsNames(container)
	for _, dnsName := range expectedEgress {
		assert.True(t, egress.Contains(dnsName), "Expected egress DNS name '%s' not found in network neighborhood", dnsName)
	}
	ingress := getIngressDnsNames(container)
	for _, dnsName := range expectedIngress {
		assert.True(t, ingress.Contains(dnsName), "Expected ingress DNS name '%s' not found in network neighborhood", dnsName)
	}
}

func getEgressDnsNames(nnc *v1beta1.NetworkNeighborhoodContainer) mapset.Set[string] {
	dns := mapset.NewSet[string]()
	for _, egress := range nnc.Egress {
		for _, dnsName := range egress.DNSNames {
			dns.Add(dnsName)
		}
	}
	return dns
}

func getIngressDnsNames(nnc *v1beta1.NetworkNeighborhoodContainer) mapset.Set[string] {
	dns := mapset.NewSet[string]()
	for _, ingress := range nnc.Ingress {
		for _, dnsName := range ingress.DNSNames {
			dns.Add(dnsName)
		}
	}
	return dns
}

func getContainerFromNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, containerName string) (*v1beta1.NetworkNeighborhoodContainer, error) {
	for _, container := range nn.Spec.Containers {
		if container.Name == containerName {
			return &container, nil
		}
	}

	for _, container := range nn.Spec.InitContainers {
		if container.Name == containerName {
			return &container, nil
		}
	}

	for _, container := range nn.Spec.EphemeralContainers {
		if container.Name == containerName {
			return &container, nil
		}
	}
	return nil, fmt.Errorf("container '%s' not found", containerName)
}
