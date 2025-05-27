//go:build component

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1client "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func tearDownTest(t *testing.T, startTime time.Time) {
	end := time.Now()

	t.Log("Waiting 30 seconds for Prometheus to scrape the data")
	time.Sleep(30 * time.Second)

	err := testutils.PlotNodeAgentPrometheusCPUUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting CPU usage: %v", err)
	}

	_, err = testutils.PlotNodeAgentPrometheusMemoryUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}

	testutils.PrintNodeAgentLogs(t)
}

func Test_01_BasicAlertTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	assert.NoError(t, wl.WaitForReady(80))

	assert.NoError(t, wl.WaitForApplicationProfile(80, "ready"))
	assert.NoError(t, wl.WaitForNetworkNeighborhood(80, "ready"))

	// process launched from nginx container
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")

	// network activity from server container
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")

	// network activity from nginx container
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")

	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}
	err = wl.WaitForNetworkNeighborhoodCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for network neighborhood to be completed: %v", err)
	}

	time.Sleep(10 * time.Second)

	appProfile, _ := wl.GetApplicationProfile()
	appProfileJson, _ := json.Marshal(appProfile)

	t.Logf("application profile: %v", string(appProfileJson))

	wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")                                           // no alert expected
	wl.ExecIntoPod([]string{"ls", "-l"}, "server")                                          // alert expected
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server") // no alert expected
	_, _, err = wl.ExecIntoPod([]string{"curl", "ebpf.io", "-m", "2"}, "nginx")             // alert expected

	// Wait for the alert to be signaled
	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "server")
	testutils.AssertNotContains(t, alerts, "Unexpected process launched", "ls", "nginx")

	testutils.AssertContains(t, alerts, "Unexpected domain request", "curl", "nginx")
	testutils.AssertNotContains(t, alerts, "Unexpected domain request", "wget", "server")

	// check network neighborhood
	nn, _ := wl.GetNetworkNeighborhood()
	testutils.AssertNetworkNeighborhoodContains(t, nn, "nginx", []string{"kubernetes.io."}, []string{})
	testutils.AssertNetworkNeighborhoodNotContains(t, nn, "server", []string{"kubernetes.io."}, []string{})

	testutils.AssertNetworkNeighborhoodContains(t, nn, "server", []string{"ebpf.io."}, []string{})
	testutils.AssertNetworkNeighborhoodNotContains(t, nn, "nginx", []string{"ebpf.io."}, []string{})
}

func Test_02_AllAlertsFromMaliciousApp(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/malicious-job.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Malicious activity will be detected in 3 minutes + 300 seconds to wait for the alerts to be generated
	maliciousAppWaitBeforeStart := time.Minute * 3
	waitBeforeLookingForAlerts := time.Minute * 5
	timer := time.NewTimer(maliciousAppWaitBeforeStart + waitBeforeLookingForAlerts)

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Wait for the alerts to be generated
	<-timer.C

	// Get all the alerts for the namespace
	alerts, err := testutils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	// Validate that all alerts are signaled
	expectedAlerts := map[string]bool{
		"Unexpected process launched":              false,
		"Unexpected file access":                   false,
		"Unexpected system call":                   false,
		"Unexpected capability used":               false,
		"Kubernetes Client Executed":               false,
		"Exec from malicious source":               false,
		"Kernel Module Load":                       false,
		"Exec Binary Not In Base Image":            false,
		"Exec from mount":                          false,
		"Unexpected Service Account Token Access":  false,
		"Unexpected domain request":                false,
		"Crypto Mining Related Port Communication": false,
		"Crypto Mining Domain Communication":       false,
	}

	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		if ruleOk {
			if _, exists := expectedAlerts[ruleName]; exists {
				expectedAlerts[ruleName] = true
			}
		}
	}

	for ruleName, signaled := range expectedAlerts {
		if !signaled {
			t.Errorf("Expected alert '%s' was not signaled", ruleName)
		}
	}
}

func Test_03_BasicLoadActivities(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Create loader
	loader, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/locust-deployment.yaml"))
	err = loader.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	loadStart := time.Now()

	// Create a load of 5 minutes
	time.Sleep(5 * time.Minute)

	loadEnd := time.Now()

	// Get CPU usage of Node Agent pods
	podToCpuUsage, err := testutils.GetNodeAgentAverageCPUUsage(loadStart, loadEnd)
	if err != nil {
		t.Errorf("Error getting CPU usage: %v", err)
	}

	if len(podToCpuUsage) == 0 {
		t.Errorf("No CPU usage data found")
	}

	for pod, cpuUsage := range podToCpuUsage {
		assert.LessOrEqual(t, cpuUsage, 0.4, "CPU usage of Node Agent is too high. CPU usage is %f, Pod: %s", cpuUsage, pod)
	}
}

func Test_04_MemoryLeak(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create 2 workloads
	wlPaths := []string{
		"resources/locust-deployment.yaml",
		"resources/nginx-deployment.yaml",
	}
	var workloads []testutils.TestWorkload
	for _, p := range wlPaths {
		wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), p))
		if err != nil {
			t.Errorf("Error creating deployment: %v", err)
		}
		workloads = append(workloads, *wl)
	}
	for _, wl := range workloads {
		err := wl.WaitForReady(80)
		if err != nil {
			t.Errorf("Error waiting for workload to be ready: %v", err)
		}
		err = wl.WaitForApplicationProfileCompletion(80)
		if err != nil {
			t.Errorf("Error waiting for application profile to be completed: %v", err)
		}
	}

	// Wait for 60 seconds for the GC to run, so the memory leak can be detected
	time.Sleep(60 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_basic", start, time.Now())
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}

	if len(metrics) == 0 {
		t.Errorf("No memory usage data found")
	}

	for _, metric := range metrics {
		podName := metric.Name
		firstValue := metric.Values[0]
		lastValue := metric.Values[len(metric.Values)-1]

		// Validate that there is no memory leak, but tolerate 100Mb memory leak
		tolerateMb := 100
		assert.LessOrEqual(t, lastValue, firstValue+float64(tolerateMb*1024*1024), "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func Test_05_MemoryLeak_10K_Alerts(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create nginx workload
	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = nginx.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	err = nginx.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to have a baseline memory usage")
	time.Sleep(300 * time.Second)

	//Exec into the nginx pod and create a file in the /tmp directory in a loop
	startLoad := time.Now()
	for i := 0; i < 100; i++ {
		_, _, err := nginx.ExecIntoPod([]string{"bash", "-c", "for i in {1..100}; do touch /tmp/nginx-test-$i; done"}, "")
		if err != nil {
			t.Errorf("Error executing remote command: %v", err)
		}
		if i%5 == 0 {
			t.Logf("Created file %d times", (i+1)*100)
		}
	}

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to GC to run")
	time.Sleep(300 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_10k_alerts", startLoad, time.Now())
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}

	if len(metrics) == 0 {
		t.Errorf("No memory usage data found")
	}

	for _, metric := range metrics {
		podName := metric.Name
		firstValue := metric.Values[0]
		lastValue := metric.Values[len(metric.Values)-1]

		// Validate that there is no memory leak, but tolerate 40mb memory leak
		tolerateMb := 40
		assert.LessOrEqual(t, lastValue, firstValue+float64(tolerateMb*1024*1024), "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func Test_06_KillProcessInTheMiddle(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()
	// Create nginx deployment
	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = nginx.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for the application profile to be created and 'ready' (not 'completed')
	err = nginx.WaitForApplicationProfile(80, "ready")
	if err != nil {
		t.Errorf("Error waiting for application profile to be 'ready': %v", err)
	}

	// Exec into the nginx pod and kill the process
	_, _, err = nginx.ExecIntoPod([]string{"bash", "-c", "kill -9 1"}, "")
	if err != nil {
		t.Errorf("Error executing remote command: %v", err)
	}

	// Wait for the application profile to be 'completed'
	err = nginx.WaitForApplicationProfileCompletion(20)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}
}

func Test_07_RuleBindingApplyTest(t *testing.T) {
	ruleBindingPath := func(name string) string {
		return path.Join(utils.CurrentDir(), "resources/rulebindings", name)
	}

	// valid
	exitCode := testutils.RunCommand("kubectl", "apply", "-f", ruleBindingPath("all-valid.yaml"))
	assert.Equal(t, 0, exitCode, "Error applying valid rule binding")
	_ = testutils.RunCommand("kubectl", "delete", "-f", ruleBindingPath("all-valid.yaml"))

	// duplicate fields
	file := ruleBindingPath("dup-fields-name-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-name-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-id-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)
}

func Test_08_ApplicationProfilePatching(t *testing.T) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	name := "replicaset-checkoutservice-59596bf8d8"
	applicationProfile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubescape.io/instance-template-hash":    "59596bf8d8",
				"kubescape.io/workload-api-group":        "apps",
				"kubescape.io/workload-api-version":      "v1",
				"kubescape.io/workload-kind":             "Deployment",
				"kubescape.io/workload-name":             "checkoutservice",
				"kubescape.io/workload-namespace":        "node-agent-test-veum",
				"kubescape.io/workload-resource-version": "667544",
			},
			Annotations: map[string]string{
				"kubescape.io/completion": "complete",
				"kubescape.io/status":     "initializing",
			},
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "server",
					Syscalls: []string{
						"capget", "capset", "chdir", "close", "epoll_ctl", "faccessat2",
						"fcntl", "fstat", "fstatfs", "futex", "getdents64", "getppid",
						"nanosleep", "newfstatat", "openat", "prctl", "read", "setgid",
						"setgroups", "setuid", "write",
					},
				},
			},
		},
		Status: v1beta1.ApplicationProfileStatus{},
	}

	_, err := storageclient.ApplicationProfiles(ns.Name).Create(context.TODO(), applicationProfile, metav1.CreateOptions{})
	assert.NoError(t, err)

	// patch the application profile
	patchOperations := []utils.PatchOperation{
		{Op: "replace", Path: "/spec/containers/0/capabilities", Value: []string{"NET_ADMIN"}},
		{Op: "add", Path: "/spec/containers/0/capabilities/-", Value: "SETGID"},
		{Op: "add", Path: "/spec/containers/0/capabilities/-", Value: "SETPCAP"},
		{Op: "add", Path: "/spec/containers/0/capabilities/-", Value: "SETUID"},
		{Op: "add", Path: "/spec/containers/0/capabilities/-", Value: "SYS_ADMIN"},
		{Op: "add", Path: "/spec/containers/0/syscalls/-", Value: "accept4"},
		{Op: "add", Path: "/spec/containers/0/syscalls/-", Value: "arch_prctl"},
		{Op: "add", Path: "/spec/containers/0/syscalls/-", Value: "bind"},
		{Op: "replace", Path: "/spec/containers/0/execs", Value: []map[string]interface{}{{
			"path": "/checkoutservice",
			"args": []string{"/checkoutservice"},
		}}},
		{Op: "add", Path: "/spec/containers/0/execs/-", Value: map[string]interface{}{
			"path": "/bin/grpc_health_probe",
			"args": []string{"/bin/grpc_health_probe", "-addr=:5050"},
		}},
		{Op: "replace", Path: "/metadata/annotations/kubescape.io~1status", Value: "ready"},
		{Op: "replace", Path: "/metadata/annotations/kubescape.io~1completion", Value: "complete"},
	}

	patch, err := json.Marshal(patchOperations)
	assert.NoError(t, err)

	// TODO use Storage abstraction?
	_, err = storageclient.ApplicationProfiles(ns.Name).Patch(context.Background(), name, types.JSONPatchType, patch, v1.PatchOptions{})

	assert.NoError(t, err)
}

func Test_09_FalsePositiveTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	testutils.IncreaseNodeAgentSniffingTime("10m")

	time.Sleep(5 * time.Second)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	t.Log("Creating services")
	_, err := testutils.CreateWorkloadsInPath(ns.Name, path.Join(utils.CurrentDir(), "resources/hipster_shop/services"))
	if err != nil {
		t.Errorf("Error creating services: %v", err)
	}

	t.Log("Creating deployments")
	deployments, err := testutils.CreateWorkloadsInPath(ns.Name, path.Join(utils.CurrentDir(), "resources/hipster_shop/deployments"))
	if err != nil {
		t.Errorf("Error creating deployments: %v", err)
	}

	t.Log("Waiting for all workloads to be ready")
	for _, wl := range deployments {
		err = wl.WaitForReady(80)
		if err != nil {
			t.Errorf("Error waiting for workload to be ready: %v", err)
		}
	}
	t.Log("All workloads are ready")

	t.Log("Waiting for all application profiles to be completed")
	for _, wl := range deployments {
		err = wl.WaitForApplicationProfileCompletion(80)
		if err != nil {
			t.Errorf("Error waiting for application profile to be completed: %v", err)
		}
	}

	// wait for 1 minute for the alerts to be generated
	time.Sleep(1 * time.Minute)

	if err != nil {
		t.Errorf("Error getting pods with restarts: %v", err)
	}

	alerts, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	assert.Equal(t, 0, len(alerts), "Expected no alerts to be generated, but got %d alerts", len(alerts))
}

func Test_10_MalwareDetectionTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	t.Log("Deploy container with malware")
	exitCode := testutils.RunCommand("kubectl", "run", "-n", ns.Name, "malware-cryptominer", "--image=quay.io/petr_ruzicka/malware-cryptominer-container:2.0.2")
	assert.Equalf(t, 0, exitCode, "expected no error when deploying malware container")

	// Wait for pod to be ready
	exitCode = testutils.RunCommand("kubectl", "wait", "--for=condition=Ready", "pod", "malware-cryptominer", "-n", ns.Name, "--timeout=300s")
	assert.Equalf(t, 0, exitCode, "expected no error when waiting for pod to be ready")

	// wait for application profile to be completed
	time.Sleep(3 * time.Minute)

	_, _, err := testutils.ExecIntoPod("malware-cryptominer", ns.Name, []string{"ls", "-l", "/usr/share/nginx/html/xmrig"}, "")
	assert.NoErrorf(t, err, "expected no error when executing command in malware container")

	_, _, err = testutils.ExecIntoPod("malware-cryptominer", ns.Name, []string{"/usr/share/nginx/html/xmrig/xmrig"}, "")

	// wait for the alerts to be generated
	time.Sleep(20 * time.Second)

	alerts, err := testutils.GetMalwareAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	expectedMalwares := []string{
		"Multios.Coinminer.Miner-6781728-2.UNOFFICIAL",
	}

	malwaresDetected := map[string]bool{}

	for _, alert := range alerts {
		podName, podNameOk := alert.Labels["pod_name"]
		malwareName, malwareNameOk := alert.Labels["malware_name"]

		if podNameOk && malwareNameOk {
			if podName == "malware-cryptominer" && slices.Contains(expectedMalwares, malwareName) {
				malwaresDetected[malwareName] = true
			}
		}
	}

	assert.Equal(t, len(expectedMalwares), len(malwaresDetected), "Expected %d malwares to be detected, but got %d malwares", len(expectedMalwares), len(malwaresDetected))
}

func Test_11_EndpointTest(t *testing.T) {
	threshold := 101
	ns := testutils.NewRandomNamespace()

	endpointTraffic, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/endpoint-traffic.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = endpointTraffic.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	assert.NoError(t, endpointTraffic.WaitForApplicationProfile(80, "ready"))

	// Merge methods
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80"}, "")
	assert.NoError(t, err)
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80", "--post-data", "test-data"}, "")

	// Merge dynamic
	for i := 0; i < threshold; i++ {
		endpointTraffic.ExecIntoPod([]string{"wget", fmt.Sprintf("http://127.0.0.1:80/users/%d", i)}, "")
	}

	// Merge headers
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80/users/99", "--header", "Connection:1234r"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80/users/12", "--header", "Connection:ziz"}, "")

	err = endpointTraffic.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	applicationProfile, err := endpointTraffic.GetApplicationProfile()
	if err != nil {
		t.Errorf("Error getting application profile: %v", err)
	}

	headers := map[string][]string{"Connection": {"close"}, "Host": {"127.0.0.1:80"}}
	rawJSON, err := json.Marshal(headers)
	assert.NoError(t, err)

	endpoint2 := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/",
		Methods:   []string{"GET", "POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON,
	}

	headers = map[string][]string{"Host": {"127.0.0.1:80"}, "Connection": {"1234r", "close", "ziz"}}
	rawJSON, err = json.Marshal(headers)
	assert.NoError(t, err)

	endpoint1 := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/users/" + dynamicpathdetector.DynamicIdentifier,
		Methods:   []string{"GET"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON,
	}

	savedEndpoints := applicationProfile.Spec.Containers[0].Endpoints

	for i := range savedEndpoints {

		headers := savedEndpoints[i].Headers
		var headersMap map[string][]string
		err := json.Unmarshal([]byte(headers), &headersMap)
		if err != nil {
			t.Errorf("Error unmarshalling headers: %v", err)
		}

		if headersMap["Connection"] != nil {
			sort.Strings(headersMap["Connection"])
			rawJSON, err = json.Marshal(headersMap)
			assert.NoError(t, err)
			savedEndpoints[i].Headers = rawJSON
		}
	}

	expectedEndpoints := []v1beta1.HTTPEndpoint{endpoint1, endpoint2}
	for _, expectedEndpoint := range expectedEndpoints {
		found := false
		for _, savedEndpoint := range savedEndpoints {
			e := savedEndpoint
			sort.Strings(e.Methods)
			sort.Strings(expectedEndpoint.Methods)
			if reflect.DeepEqual(e, expectedEndpoint) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected endpoint %v not found in the application profile", expectedEndpoint)
		}
	}
}

func Test_12_MergingProfilesTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// PHASE 1: Setup workload and initial profile
	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	require.NoError(t, err, "Failed to create workload")
	require.NoError(t, wl.WaitForReady(80), "Workload failed to be ready")
	require.NoError(t, wl.WaitForApplicationProfile(80, "ready"), "Application profile not ready")

	// Generate initial profile data
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")
	require.NoError(t, err, "Failed to exec into nginx container")
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")
	require.NoError(t, err, "Failed to exec into server container")

	require.NoError(t, wl.WaitForApplicationProfileCompletion(80), "Profile failed to complete")
	time.Sleep(10 * time.Second) // Allow profile processing

	// Log initial profile state
	initialProfile, err := wl.GetApplicationProfile()
	require.NoError(t, err, "Failed to get initial profile")
	initialProfileJSON, _ := json.Marshal(initialProfile)
	t.Logf("Initial application profile:\n%s", string(initialProfileJSON))

	// PHASE 2: Verify initial alerts
	t.Log("Testing initial alert generation...")
	wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")  // Expected: no alert
	wl.ExecIntoPod([]string{"ls", "-l"}, "server") // Expected: alert
	time.Sleep(30 * time.Second)                   // Wait for alert generation

	initialAlerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get initial alerts")

	// Record initial alert count
	initialAlertCount := 0
	for _, alert := range initialAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
			initialAlertCount++
		}
	}

	testutils.AssertContains(t, initialAlerts, "Unexpected process launched", "ls", "server")
	testutils.AssertNotContains(t, initialAlerts, "Unexpected process launched", "ls", "nginx")

	// PHASE 3: Apply user-managed profile
	t.Log("Applying user-managed profile...")
	// Create the user-managed profile
	userProfile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("ug-%s", initialProfile.Name),
			Namespace: initialProfile.Namespace,
			Annotations: map[string]string{
				"kubescape.io/managed-by": "User",
			},
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Architectures: []string{"amd64"},
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "nginx",
					Execs: []v1beta1.ExecCalls{
						{
							Path: "/usr/bin/ls",
							Args: []string{"/usr/bin/ls", "-l"},
						},
					},
					SeccompProfile: v1beta1.SingleSeccompProfile{
						Spec: v1beta1.SingleSeccompProfileSpec{
							DefaultAction: "",
						},
					},
				},
				{
					Name: "server",
					Execs: []v1beta1.ExecCalls{
						{
							Path: "/bin/ls",
							Args: []string{"/bin/ls", "-l"},
						},
						{
							Path: "/bin/grpc_health_probe",
							Args: []string{"-addr=:9555"},
						},
					},
					SeccompProfile: v1beta1.SingleSeccompProfile{
						Spec: v1beta1.SingleSeccompProfileSpec{
							DefaultAction: "",
						},
					},
				},
			},
		},
	}

	// Log the profile we're about to create
	userProfileJSON, err := json.MarshalIndent(userProfile, "", "  ")
	require.NoError(t, err, "Failed to marshal user profile")
	t.Logf("Creating user profile:\n%s", string(userProfileJSON))

	// Get k8s client
	k8sClient := k8sinterface.NewKubernetesApi()

	// Create the user-managed profile
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
	_, err = storageClient.ApplicationProfiles(ns.Name).Create(context.Background(), userProfile, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create user profile")

	// PHASE 4: Verify merged profile behavior
	t.Log("Verifying merged profile behavior...")
	time.Sleep(15 * time.Second) // Allow merge to complete

	// Test merged profile behavior
	wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")  // Expected: no alert
	wl.ExecIntoPod([]string{"ls", "-l"}, "server") // Expected: no alert (user profile should suppress alert)
	time.Sleep(10 * time.Second)                   // Wait for potential alerts

	// Verify alert counts
	finalAlerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get final alerts")

	// Only count new alerts (after the initial count)
	newAlertCount := 0
	for _, alert := range finalAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
			newAlertCount++
		}
	}

	t.Logf("Alert counts - Initial: %d, Final: %d", initialAlertCount, newAlertCount)

	if newAlertCount > initialAlertCount {
		t.Logf("Full alert details:")
		for _, alert := range finalAlerts {
			if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
				t.Logf("Alert: %+v", alert)
			}
		}
		t.Errorf("New alerts were generated after merge (Initial: %d, Final: %d)", initialAlertCount, newAlertCount)
	}

	// PHASE 5: Check PATCH (removing the ls command from the user profile of the server container and triggering an alert)
	t.Log("Patching user profile to remove ls command from server container...")
	patchOperations := []utils.PatchOperation{
		{Op: "remove", Path: "/spec/containers/1/execs/0"},
	}

	patch, err := json.Marshal(patchOperations)
	require.NoError(t, err, "Failed to marshal patch operations")

	_, err = storageClient.ApplicationProfiles(ns.Name).Patch(context.Background(), userProfile.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
	require.NoError(t, err, "Failed to patch user profile")

	// Verify patched profile behavior
	time.Sleep(15 * time.Second) // Allow merge to complete

	// Log the profile that was patched
	patchedProfile, err := wl.GetApplicationProfile()
	require.NoError(t, err, "Failed to get patched profile")
	t.Logf("Patched application profile:\n%v", patchedProfile)

	// Test patched profile behavior
	wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")  // Expected: no alert
	wl.ExecIntoPod([]string{"ls", "-l"}, "server") // Expected: alert (ls command removed from user profile)
	time.Sleep(10 * time.Second)                   // Wait for potential alerts

	// Verify alert counts
	finalAlerts, err = testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get final alerts")

	// Only count new alerts (after the initial count)
	newAlertCount = 0
	for _, alert := range finalAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
			newAlertCount++
		}
	}

	t.Logf("Alert counts - Initial: %d, Final: %d", initialAlertCount, newAlertCount)

	if newAlertCount <= initialAlertCount {
		t.Logf("Full alert details:")
		for _, alert := range finalAlerts {
			if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
				t.Logf("Alert: %+v", alert)
			}
		}
		t.Errorf("New alerts were not generated after patch (Initial: %d, Final: %d)", initialAlertCount, newAlertCount)
	}
}

func Test_13_MergingNetworkNeighborhoodTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// PHASE 1: Setup workload and initial network neighborhood
	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	require.NoError(t, err, "Failed to create workload")
	require.NoError(t, wl.WaitForReady(80), "Workload failed to be ready")
	require.NoError(t, wl.WaitForNetworkNeighborhood(80, "ready"), "Network neighborhood not ready")

	// Generate initial network data
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")
	require.NoError(t, err, "Failed to exec wget in server container")
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")
	require.NoError(t, err, "Failed to exec curl in nginx container")

	require.NoError(t, wl.WaitForNetworkNeighborhoodCompletion(80), "Network neighborhood failed to complete")
	time.Sleep(10 * time.Second) // Allow network neighborhood processing

	// Log initial network neighborhood state
	initialNN, err := wl.GetNetworkNeighborhood()
	require.NoError(t, err, "Failed to get initial network neighborhood")
	initialNNJSON, _ := json.Marshal(initialNN)
	t.Logf("Initial network neighborhood:\n%s", string(initialNNJSON))

	// PHASE 2: Verify initial alerts
	t.Log("Testing initial alert generation...")
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")         // Expected: no alert (original rule)
	_, _, err = wl.ExecIntoPod([]string{"wget", "httpforever.com", "-T", "2", "-t", "1"}, "server") // Expected: alert (not allowed)
	_, _, err = wl.ExecIntoPod([]string{"wget", "httpforever.com", "-T", "2", "-t", "1"}, "server") // Expected: alert (not allowed)
	_, _, err = wl.ExecIntoPod([]string{"wget", "httpforever.com", "-T", "2", "-t", "1"}, "server") // Expected: alert (not allowed)
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")               // Expected: no alert (original rule)
	_, _, err = wl.ExecIntoPod([]string{"curl", "github.com", "-m", "2"}, "nginx")                  // Expected: alert (not allowed)
	time.Sleep(30 * time.Second)                                                                    // Wait for alert generation

	initialAlerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get initial alerts")

	// Record initial alert count
	initialAlertCount := 0
	for _, alert := range initialAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected domain request" && alert.Labels["container_name"] == "server" {
			initialAlertCount++
		}
	}

	// Verify initial alerts
	testutils.AssertContains(t, initialAlerts, "Unexpected domain request", "wget", "server")
	testutils.AssertContains(t, initialAlerts, "Unexpected domain request", "curl", "nginx")

	// PHASE 3: Apply user-managed network neighborhood
	t.Log("Applying user-managed network neighborhood...")
	userNN := &v1beta1.NetworkNeighborhood{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("ug-%s", initialNN.Name),
			Namespace: initialNN.Namespace,
			Annotations: map[string]string{
				"kubescape.io/managed-by": "User",
			},
		},
		Spec: v1beta1.NetworkNeighborhoodSpec{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "multiple-containers-app",
				},
			},
			Containers: []v1beta1.NetworkNeighborhoodContainer{
				{
					Name: "nginx",
					Egress: []v1beta1.NetworkNeighbor{
						{
							Identifier: "nginx-github",
							Type:       "external",
							DNSNames:   []string{"github.com."},
							Ports: []v1beta1.NetworkPort{
								{
									Name:     "TCP-80",
									Protocol: "TCP",
									Port:     ptr.To(int32(80)),
								},
								{
									Name:     "TCP-443",
									Protocol: "TCP",
									Port:     ptr.To(int32(443)),
								},
							},
						},
					},
				},
				{
					Name: "server",
					Egress: []v1beta1.NetworkNeighbor{
						{
							Identifier: "server-example",
							Type:       "external",
							DNSNames:   []string{"info.cern.ch."},
							Ports: []v1beta1.NetworkPort{
								{
									Name:     "TCP-80",
									Protocol: "TCP",
									Port:     ptr.To(int32(80)),
								},
								{
									Name:     "TCP-443",
									Protocol: "TCP",
									Port:     ptr.To(int32(443)),
								},
							},
						},
					},
				},
			},
		},
	}

	// Create user-managed network neighborhood
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
	_, err = storageClient.NetworkNeighborhoods(ns.Name).Create(context.Background(), userNN, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create user network neighborhood")

	// PHASE 4: Verify merged behavior (no new alerts)
	t.Log("Verifying merged network neighborhood behavior...")
	time.Sleep(25 * time.Second) // Allow merge to complete

	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server") // Expected: no alert (original)
	// Try multiple times to ensure alert is removed
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: no alert (user added)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: no alert (user added)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: no alert (user added)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: no alert (user added)
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")            // Expected: no alert (original)
	_, _, err = wl.ExecIntoPod([]string{"curl", "github.com", "-m", "2"}, "nginx")               // Expected: no alert (user added)
	time.Sleep(30 * time.Second)                                                                 // Wait for potential alerts

	mergedAlerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get alerts after merge")

	// Count new alerts after merge
	newAlertCount := 0
	for _, alert := range mergedAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected domain request" && alert.Labels["container_name"] == "server" {
			newAlertCount++
		}
	}

	t.Logf("Alert counts - Initial: %d, After merge: %d", initialAlertCount, newAlertCount)

	if newAlertCount > initialAlertCount {
		t.Logf("Full alert details:")
		for _, alert := range mergedAlerts {
			if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected domain request" && alert.Labels["container_name"] == "server" {
				t.Logf("Alert: %+v", alert)
			}
		}
		t.Errorf("New alerts were generated after merge (Initial: %d, After merge: %d)", initialAlertCount, newAlertCount)
	}

	// PHASE 5: Remove permission via patch and verify alerts return
	t.Log("Patching user network neighborhood to remove info.cern.ch from server container...")
	patchOperations := []utils.PatchOperation{
		{Op: "remove", Path: "/spec/containers/1/egress/0"},
	}

	patch, err := json.Marshal(patchOperations)
	require.NoError(t, err, "Failed to marshal patch operations")

	_, err = storageClient.NetworkNeighborhoods(ns.Name).Patch(context.Background(), userNN.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
	require.NoError(t, err, "Failed to patch user network neighborhood")

	time.Sleep(20 * time.Second) // Allow merge to complete

	// Test alerts after patch
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server") // Expected: no alert
	// Try multiple times to ensure alert is removed
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: alert (removed)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: alert (removed)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: alert (removed)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: alert (removed)
	_, _, err = wl.ExecIntoPod([]string{"wget", "info.cern.ch", "-T", "2", "-t", "1"}, "server") // Expected: alert (removed)
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")            // Expected: no alert
	_, _, err = wl.ExecIntoPod([]string{"curl", "github.com", "-m", "2"}, "nginx")               // Expected: no alert
	time.Sleep(30 * time.Second)                                                                 // Wait for alerts

	finalAlerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get final alerts")

	// Count final alerts
	finalAlertCount := 0
	for _, alert := range finalAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected domain request" && alert.Labels["container_name"] == "server" {
			finalAlertCount++
		}
	}

	t.Logf("Alert counts - Initial: %d, Final: %d", initialAlertCount, finalAlertCount)

	if finalAlertCount <= initialAlertCount {
		t.Logf("Full alert details:")
		for _, alert := range finalAlerts {
			if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected domain request" && alert.Labels["container_name"] == "server" {
				t.Logf("Alert: %+v", alert)
			}
		}
		t.Errorf("New alerts were not generated after patch (Initial: %d, Final: %d)", initialAlertCount, finalAlertCount)
	}
}

func Test_14_RulePoliciesTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	endpointTraffic, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/endpoint-traffic.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = endpointTraffic.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for application profile to be ready
	assert.NoError(t, endpointTraffic.WaitForApplicationProfile(80, "ready"))

	// Add to rule policy symlink
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "-s", "/etc/shadow", "/tmp/a"}, "")
	assert.NoError(t, err)

	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// Not add to rule policy
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "/bin/sh", "/tmp/a"}, "")
	assert.NoError(t, err)

	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	err = endpointTraffic.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	applicationProfile, err := endpointTraffic.GetApplicationProfile()
	if err != nil {
		t.Errorf("Error getting application profile: %v", err)
	}

	symlinkPolicy := applicationProfile.Spec.Containers[0].PolicyByRuleId[ruleengine.R1010ID]
	assert.Equal(t, []string{"ln"}, symlinkPolicy.AllowedProcesses)

	hardlinkPolicy := applicationProfile.Spec.Containers[0].PolicyByRuleId[ruleengine.R1012ID]
	assert.Len(t, hardlinkPolicy.AllowedProcesses, 0)

	fmt.Println("After completed....")

	// wait for cache
	time.Sleep(120 * time.Second)

	// generate hardlink alert
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "/etc/shadow", "/tmp/a"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// not generate alert
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "-s", "/etc/shadow", "/tmp/a"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// Wait for the alert to be signaled
	time.Sleep(60 * time.Second)

	alerts, err := testutils.GetAlerts(endpointTraffic.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	testutils.AssertContains(t, alerts, "Hardlink Created Over Sensitive File", "ln", "endpoint-traffic")
	testutils.AssertNotContains(t, alerts, "Symlink Created Over Sensitive File", "ln", "endpoint-traffic")
}

func Test_15_CompletedApCannotBecomeReadyAgain(t *testing.T) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	ns := testutils.NewRandomNamespace()
	defer func() {
		_ = k8sClient.KubernetesClient.CoreV1().Namespaces().Delete(context.Background(), ns.Name, v1.DeleteOptions{})
	}()

	// create an application profile with completed status
	name := "test"
	ap1, err := storageclient.ApplicationProfiles(ns.Name).Create(context.TODO(), &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}, v1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, helpersv1.Completed, ap1.Annotations[helpersv1.StatusMetadataKey])

	// patch the application profile with ready status
	patchOperations := []utils.PatchOperation{
		{
			Op:    "replace",
			Path:  "/metadata/annotations/" + utils.EscapeJSONPointerElement(helpersv1.StatusMetadataKey),
			Value: helpersv1.Ready,
		},
	}
	patch, err := json.Marshal(patchOperations)
	require.NoError(t, err)
	ap2, err := storageclient.ApplicationProfiles(ns.Name).Patch(context.Background(), name, types.JSONPatchType, patch, v1.PatchOptions{})
	assert.NoError(t, err)                                                             // patch should succeed
	assert.Equal(t, helpersv1.Completed, ap2.Annotations[helpersv1.StatusMetadataKey]) // but the status should not change
}

func Test_16_ApNotStuckOnRestart(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	time.Sleep(30 * time.Second)

	_, _, _ = wl.ExecIntoPod([]string{"service", "nginx", "stop"}, "") // suppose to get error
	assert.NoError(t, wl.WaitForReady(80))
	assert.NoError(t, wl.WaitForApplicationProfileCompletion(80))

	time.Sleep(30 * time.Second)

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	assert.NoError(t, err)

	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx")
}

func Test_17_ApCompletedToPartialUpdateTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	time.Sleep(30 * time.Second)
	assert.NoError(t, wl.WaitForReady(80))
	assert.NoError(t, wl.WaitForNetworkNeighborhood(80, "ready"))

	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	assert.NoError(t, err)

	assert.NoError(t, wl.WaitForApplicationProfileCompletion(160))
	assert.NoError(t, wl.WaitForNetworkNeighborhoodCompletion(160))

	time.Sleep(30 * time.Second)

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	assert.NoError(t, err)

	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx")
}

func Test_18_ShortLivedJobTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	// Create a short-lived job
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/echo-job.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Application profile should be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}
}

func Test_19_AlertOnPartialProfileTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	if err != nil {
		t.Errorf("Error restarting daemonset: %v", err)
	}
	assert.NoError(t, err)

	// Wait for the application profile to be completed
	err = wl.WaitForApplicationProfileCompletion(160)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by executing a command
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	if err != nil {
		t.Errorf("Error executing command in pod: %v", err)
	}
	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx")
}

func Test_20_AlertOnPartialThenLearnProcessTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	if err != nil {
		t.Errorf("Error restarting daemonset: %v", err)
	}
	assert.NoError(t, err)

	// Wait for the application profile to be completed (partial)
	err = wl.WaitForApplicationProfileCompletion(160)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by executing a command (should trigger alert on partial profile)
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	if err != nil {
		t.Errorf("Error executing command in pod: %v", err)
	}

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx")

	profile, err := wl.GetApplicationProfile()
	if err != nil {
		t.Errorf("Error getting application profile: %v", err)
	}

	// Restart the deployment to reset the profile learning
	err = testutils.RestartDeployment(ns.Name, wl.WorkloadObj.GetName())
	if err != nil {
		t.Errorf("Error restarting deployment: %v", err)
	}

	wl, err = testutils.NewTestWorkloadFromK8sIdentifiers(ns.Name, wl.UnstructuredObj.GroupVersionKind().Kind, "nginx-deployment")
	if err != nil {
		t.Errorf("Error re-fetching workload after restart: %v", err)
	}

	// Wait for the workload to be ready after restart
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready after restart: %v", err)
	}

	// Execute the same command during learning phase (should be learned in profile)
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	if err != nil {
		t.Errorf("Error executing command in pod during learning: %v", err)
	}

	// Wait for the application profile to be completed (with ls command learned)
	err = wl.WaitForApplicationProfileCompletionWithBlacklist(160, []string{profile.Name})
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed after learning: %v", err)
	}

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Execute the same command again - should NOT trigger an alert now
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	if err != nil {
		t.Errorf("Error executing command in pod after learning: %v", err)
	}

	// Wait to see if any alert is generated
	time.Sleep(15 * time.Second)
	alertsAfter, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts after learning: %v", err)
	}

	// Should not contain new alert for ls command after learning
	count := 0
	for _, alert := range alertsAfter {
		if alert.Labels["rule_name"] == "Unexpected process launched" && alert.Labels["container_name"] == "nginx" && alert.Labels["process_name"] == "ls" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("Unexpected alerts found after learning: %d", count)
	}
}

func Test_21_AlertOnPartialThenLearnNetworkTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload using deployment-multiple-containers.yaml (same as Test_22)
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	if err != nil {
		t.Errorf("Error restarting daemonset: %v", err)
	}
	assert.NoError(t, err)

	// Wait for the network neighborhood to be completed (partial)
	err = wl.WaitForNetworkNeighborhoodCompletion(160)
	if err != nil {
		t.Errorf("Error waiting for network neighborhood to be completed: %v", err)
	}

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by making a network request (should trigger alert on partial profile)
	// Using curl with timeout and targeting nginx container (same as Test_22)
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	if err != nil {
		t.Errorf("Error executing network command in pod: %v", err)
	}

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}
	testutils.AssertContains(t, alerts, "Unexpected domain request", "curl", "nginx")

	nn, err := wl.GetNetworkNeighborhood()
	if err != nil {
		t.Errorf("Error getting network neighborhood: %v", err)
	}

	// Restart the deployment to reset the profile learning
	err = testutils.RestartDeployment(ns.Name, wl.WorkloadObj.GetName())
	if err != nil {
		t.Errorf("Error restarting deployment: %v", err)
	}

	wl, err = testutils.NewTestWorkloadFromK8sIdentifiers(ns.Name, wl.UnstructuredObj.GroupVersionKind().Kind, "multiple-containers-deployment")
	if err != nil {
		t.Errorf("Error re-fetching workload after restart: %v", err)
	}

	// Wait for the workload to be ready after restart
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready after restart: %v", err)
	}

	// Execute the same network command during learning phase (should be learned in profile)
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	if err != nil {
		t.Errorf("Error executing network command in pod during learning: %v", err)
	}

	// Wait for the network neighborhood to be completed (with curl command learned)
	err = wl.WaitForNetworkNeighborhoodCompletionWithBlacklist(160, []string{nn.Name})
	if err != nil {
		t.Errorf("Error waiting for network neighborhood to be completed after learning: %v", err)
	}

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Execute the same network command again - should NOT trigger an alert now
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	if err != nil {
		t.Errorf("Error executing network command in pod after learning: %v", err)
	}

	// Wait to see if any alert is generated
	time.Sleep(15 * time.Second)
	alertsAfter, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts after learning: %v", err)
	}

	// Should not contain new alert for curl command after learning
	count := 0
	for _, alert := range alertsAfter {
		if alert.Labels["rule_name"] == "Unexpected domain request" && alert.Labels["container_name"] == "nginx" && alert.Labels["process_name"] == "curl" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("Unexpected alerts found after learning: %d", count)
	}
}

func Test_22_AlertOnPartialNetworkProfileTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	if err != nil {
		t.Errorf("Error restarting daemonset: %v", err)
	}
	assert.NoError(t, err)

	// Wait for the network neighborhood to be completed
	err = wl.WaitForNetworkNeighborhoodCompletion(160)
	if err != nil {
		t.Errorf("Error waiting for network neighborhood to be completed: %v", err)
	}

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by making an unexpected network request
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	if err != nil {
		t.Errorf("Error executing network command in pod: %v", err)
	}

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}
	testutils.AssertContains(t, alerts, "Unexpected domain request", "curl", "nginx")
}
