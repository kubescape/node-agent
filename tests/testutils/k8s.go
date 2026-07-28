package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	eventsv1 "k8s.io/api/events/v1"
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

	return ExecIntoPod(pod.Name, w.Namespace, command, container)
}
func NewTestWorkloadFromK8sIdentifiers(namespace, kind, name string) (*TestWorkload, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	gvr, err := k8sinterface.GetGroupVersionResource(kind)
	if err != nil {
		return nil, err
	}
	clientResource := k8sClient.DynamicClient.Resource(gvr)
	obj, err := clientResource.Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get workload %s/%s: %w", namespace, name, err)
	}
	objData, err := json.Marshal(obj.Object)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}
	wl, err := workloadinterface.NewWorkload(objData)
	if err != nil {
		return nil, fmt.Errorf("failed to create workload from object: %w", err)
	}
	return &TestWorkload{
		Namespace:       namespace,
		UnstructuredObj: obj,
		WorkloadObj:     wl,
		client:          clientResource.Namespace(namespace),
	}, nil
}

func ExecIntoPod(podName, podNamespace string, command []string, container string) (string, string, error) {
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
		Namespace(podNamespace).
		Resource("pods").
		Name(podName).
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
		return "", "", fmt.Errorf("%w Failed executing command %s on %v/%v", err, command, podNamespace, podName)
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

// The unified ContainerProfile (spdx.softwarecomposition.kubescape.io) replaces
// the former per-workload ApplicationProfile and NetworkNeighborhood CRDs. It is
// authored/learnt per container: a workload with N containers yields N
// ContainerProfiles, each carrying the flat spec (execs/opens/capabilities/
// syscalls/endpoints/egress/ingress) that used to live under a container entry
// of an AP/NN. Profiles are matched to a workload by the kubescape.io/workload-*
// labels and to a container by kubescape.io/workload-container-name.

func (w *TestWorkload) listContainerProfilesInNamespace() ([]v1beta1.ContainerProfile, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	profiles, err := storageclient.ContainerProfiles(w.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return profiles.Items, nil
}

// matchingContainerProfiles returns every ContainerProfile whose workload labels
// identify this workload (one per learnt/authored container).
func (w *TestWorkload) matchingContainerProfiles() ([]v1beta1.ContainerProfile, error) {
	cps, err := w.listContainerProfilesInNamespace()
	if err != nil {
		return nil, err
	}
	var matching []v1beta1.ContainerProfile
	for _, cp := range cps {
		wlKind := cp.Labels["kubescape.io/workload-kind"]
		wlName := cp.Labels["kubescape.io/workload-name"]
		wlNs := cp.Labels["kubescape.io/workload-namespace"]
		if wlKind == w.WorkloadObj.GetKind() && wlName == w.WorkloadObj.GetName() && wlNs == w.Namespace {
			matching = append(matching, cp)
		}
	}
	return matching, nil
}

// GetContainerProfile returns the newest ContainerProfile for the named
// container of this workload.
func (w *TestWorkload) GetContainerProfile(containerName string) (*v1beta1.ContainerProfile, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	matching, err := w.matchingContainerProfiles()
	if err != nil {
		return nil, err
	}

	var candidates []v1beta1.ContainerProfile
	for _, cp := range matching {
		if cp.Labels["kubescape.io/workload-container-name"] == containerName {
			candidates = append(candidates, cp)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("container profile for container %q not found", containerName)
	}

	newest := &candidates[0]
	for i := 1; i < len(candidates); i++ {
		if candidates[i].CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = &candidates[i]
		}
	}
	return storageclient.ContainerProfiles(w.Namespace).Get(context.TODO(), newest.Name, metav1.GetOptions{})
}

// GetContainerProfiles returns the newest ContainerProfile per container name
// for this workload.
func (w *TestWorkload) GetContainerProfiles() ([]v1beta1.ContainerProfile, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	matching, err := w.matchingContainerProfiles()
	if err != nil {
		return nil, err
	}
	if len(matching) == 0 {
		return nil, fmt.Errorf("container profile not found")
	}

	newestByContainer := map[string]*v1beta1.ContainerProfile{}
	for i := range matching {
		cp := &matching[i]
		name := cp.Labels["kubescape.io/workload-container-name"]
		if cur, ok := newestByContainer[name]; !ok || cp.CreationTimestamp.After(cur.CreationTimestamp.Time) {
			newestByContainer[name] = cp
		}
	}

	var out []v1beta1.ContainerProfile
	for _, cp := range newestByContainer {
		full, err := storageclient.ContainerProfiles(w.Namespace).Get(context.TODO(), cp.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		out = append(out, *full)
	}
	return out, nil
}

func (w *TestWorkload) WaitForContainerProfileCompletion(maxRetries uint64) error {
	return w.WaitForContainerProfile(maxRetries, "completed")
}

func (w *TestWorkload) WaitForContainerProfileCompletionWithBlacklist(maxRetries uint64, blacklist []string) error {
	return backoff.RetryNotify(func() error {
		cps, err := w.matchingContainerProfiles()
		if err != nil {
			return err
		}
		if len(cps) == 0 {
			return fmt.Errorf("no container profiles found")
		}
		for i := range cps {
			if cps[i].Annotations["kubescape.io/status"] != "completed" {
				return fmt.Errorf("container profile %s is not in status 'completed'", cps[i].Name)
			}
			for _, item := range blacklist {
				if cps[i].Name == item {
					return fmt.Errorf("container profile %s is blacklisted", item)
				}
			}
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Second), maxRetries), func(err error, d time.Duration) {
		logger.L().Info("waiting for container profile", helpers.Error(err), helpers.String("retry in", d.String()), helpers.String("current time", time.Now().Format(time.RFC3339)))
	})
}

func (w *TestWorkload) WaitForContainerProfile(maxRetries uint64, expectedStatus string) error {
	return backoff.RetryNotify(func() error {
		cps, err := w.matchingContainerProfiles()
		if err != nil {
			return err
		}
		if len(cps) == 0 {
			return fmt.Errorf("no container profiles found")
		}
		for i := range cps {
			if cps[i].Annotations["kubescape.io/status"] != expectedStatus {
				return fmt.Errorf("container profile %s is not in status '%s'", cps[i].Name, expectedStatus)
			}
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Second), maxRetries), func(err error, d time.Duration) {
		logger.L().Info("waiting for container profile", helpers.Error(err), helpers.String("retry in", d.String()), helpers.String("current time", time.Now().Format(time.RFC3339)))
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
	var workloads []TestWorkload
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

// AssertContainerProfileNotContains asserts that none of the given egress/ingress
// DNS names appear in the container profile's learnt network surface. The
// ContainerProfile is already scoped to a single container, so there is no
// container-name argument (unlike the former per-workload NetworkNeighborhood).
func AssertContainerProfileNotContains(t *testing.T, cp *v1beta1.ContainerProfile, notExpectedEgress, notExpectedIngress []string) {
	egress := getEgressDnsNames(cp)
	for _, dnsName := range notExpectedEgress {
		assert.False(t, egress.Contains(dnsName), "did not expect egress DNS name '%s' in container profile", dnsName)
	}
	ingress := getIngressDnsNames(cp)
	for _, dnsName := range notExpectedIngress {
		assert.False(t, ingress.Contains(dnsName), "did not expect ingress DNS name '%s' in container profile", dnsName)
	}
}

// AssertContainerProfileContains asserts that all of the given egress/ingress
// DNS names appear in the container profile's learnt network surface.
func AssertContainerProfileContains(t *testing.T, cp *v1beta1.ContainerProfile, expectedEgress, expectedIngress []string) {
	egress := getEgressDnsNames(cp)
	for _, dnsName := range expectedEgress {
		assert.True(t, egress.Contains(dnsName), "Expected egress DNS name '%s' not found in container profile", dnsName)
	}
	ingress := getIngressDnsNames(cp)
	for _, dnsName := range expectedIngress {
		assert.True(t, ingress.Contains(dnsName), "Expected ingress DNS name '%s' not found in container profile", dnsName)
	}
}

func getEgressDnsNames(cp *v1beta1.ContainerProfile) mapset.Set[string] {
	dns := mapset.NewSet[string]()
	for _, egress := range cp.Spec.Egress {
		for _, dnsName := range egress.DNSNames {
			dns.Add(dnsName)
		}
	}
	return dns
}

func getIngressDnsNames(cp *v1beta1.ContainerProfile) mapset.Set[string] {
	dns := mapset.NewSet[string]()
	for _, ingress := range cp.Spec.Ingress {
		for _, dnsName := range ingress.DNSNames {
			dns.Add(dnsName)
		}
	}
	return dns
}

func PrintAppLogs(t *testing.T, app string) {
	k8sClient := k8sinterface.NewKubernetesApi()
	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}
	pods, err := k8sClient.KubernetesClient.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
	})
	if err != nil {
		t.Errorf("error getting %s pods: %v", app, err)
		return
	}

	for _, pod := range pods.Items {
		buf := &bytes.Buffer{}

		request := k8sClient.KubernetesClient.CoreV1().RESTClient().
			Get().
			Namespace(pod.Namespace).
			Name(pod.Name).
			Resource("pods").
			SubResource("log").
			VersionedParams(&v1.PodLogOptions{
				Follow:    false,
				Previous:  false,
				Container: app,
			}, scheme.ParameterCodec)

		readCloser, err := request.Stream(context.TODO())
		if err != nil {
			t.Errorf("error getting log stream: %v", err)
			return
		}
		_, err = io.Copy(buf, readCloser)
		if err != nil {
			t.Errorf("error copying log stream: %v", err)
			return
		}

		t.Logf("---- Logs for pod: %s ----", pod.Name)
		t.Log(buf.String())
		t.Logf("---- End of logs for pod: %s ----", pod.Name)
		readCloser.Close()
	}
}

func RestartDaemonSet(namespace, name string) error {
	k8sClient := k8sinterface.NewKubernetesApi()
	ctx := context.TODO()

	// Get the daemonset
	daemonset, err := k8sClient.KubernetesClient.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get daemonset %s/%s: %w", namespace, name, err)
	}

	// Add or update the restart annotation
	if daemonset.Spec.Template.ObjectMeta.Annotations == nil {
		daemonset.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}
	daemonset.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

	// Update the daemonset
	_, err = k8sClient.KubernetesClient.AppsV1().DaemonSets(namespace).Update(ctx, daemonset, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update daemonset %s/%s: %w", namespace, name, err)
	}

	// Wait for the daemonset to be ready
	err = backoff.RetryNotify(func() error {
		updatedDS, err := k8sClient.KubernetesClient.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if updatedDS.Status.NumberReady != updatedDS.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not ready: %d/%d pods ready",
				namespace, name, updatedDS.Status.NumberReady, updatedDS.Status.DesiredNumberScheduled)
		}

		if updatedDS.Status.UpdatedNumberScheduled != updatedDS.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not updated: %d/%d pods updated",
				namespace, name, updatedDS.Status.UpdatedNumberScheduled, updatedDS.Status.DesiredNumberScheduled)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(5*time.Second), 30), func(err error, d time.Duration) {
		logger.L().Info("waiting for daemonset to be ready",
			helpers.String("daemonset", name),
			helpers.String("namespace", namespace),
			helpers.Error(err),
			helpers.String("retry in", d.String()))
	})

	return err
}

func (w *TestWorkload) Delete() error {
	if w.client == nil {
		return fmt.Errorf("workload client is nil, workload may not have been created properly")
	}

	// Delete the workload using the dynamic client
	deletePolicy := metav1.DeletePropagationForeground
	deleteOptions := metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}

	err := w.client.Delete(context.TODO(), w.WorkloadObj.GetName(), deleteOptions)
	if err != nil {
		return fmt.Errorf("failed to delete workload %s/%s: %w", w.Namespace, w.WorkloadObj.GetName(), err)
	}

	// Delete the namespace
	k8sClient := k8sinterface.NewKubernetesApi()
	err = k8sClient.KubernetesClient.CoreV1().Namespaces().Delete(context.TODO(), w.Namespace, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete namespace %s: %w", w.Namespace, err)
	}

	return nil
}

func (w *TestWorkload) GetWorkloadEvents() ([]eventsv1.Event, error) {
	k8sClient := k8sinterface.NewKubernetesApi()
	events, err := k8sClient.KubernetesClient.EventsV1().Events(w.Namespace).List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("regarding.kind=%s,regarding.name=%s", w.WorkloadObj.GetKind(), w.WorkloadObj.GetName()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}
	return events.Items, nil
}

func RestartDeployment(namespace, name string) error {
	k8sClient := k8sinterface.NewKubernetesApi()
	ctx := context.TODO()

	// Get the deployment
	deployment, err := k8sClient.KubernetesClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment %s/%s: %w", namespace, name, err)
	}

	// Add or update the restart annotation
	if deployment.Spec.Template.ObjectMeta.Annotations == nil {
		deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}
	deployment.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

	// Update the deployment
	_, err = k8sClient.KubernetesClient.AppsV1().Deployments(namespace).Update(ctx, deployment, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update deployment %s/%s: %w", namespace, name, err)
	}

	// Wait for the deployment to be ready
	err = backoff.RetryNotify(func() error {
		updatedDeployment, err := k8sClient.KubernetesClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if updatedDeployment.Status.AvailableReplicas < updatedDeployment.Status.Replicas {
			return fmt.Errorf("deployment %s/%s not ready: %d/%d replicas available",
				namespace, name, updatedDeployment.Status.AvailableReplicas, updatedDeployment.Status.Replicas)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(5*time.Second), 30), func(err error, d time.Duration) {
		logger.L().Info("waiting for deployment to be ready",
			helpers.String("deployment", name),
			helpers.String("namespace", namespace),
			helpers.Error(err),
			helpers.String("retry in", d.String()))
	})

	return err
}
