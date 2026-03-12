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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
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
	require.NoError(t, err, "Error plotting CPU usage")

	_, err = testutils.PlotNodeAgentPrometheusMemoryUsage(t.Name(), startTime, end)
	require.NoError(t, err, "Error plotting memory usage")

	testutils.PrintAppLogs(t, "node-agent")
	testutils.PrintAppLogs(t, "malicious-app")
	testutils.PrintAppLogs(t, "endpoint-traffic")
}

func Test_01_BasicAlertTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	require.NoError(t, err, "Error creating workload")
	require.NoError(t, wl.WaitForReady(80))

	time.Sleep(10 * time.Second)

	// process launched from nginx container
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")

	// network activity from server container
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")

	// network activity from nginx container
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")

	err = wl.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")
	err = wl.WaitForNetworkNeighborhoodCompletion(80)
	require.NoError(t, err, "Error waiting for network neighborhood to be completed")

	time.Sleep(30 * time.Second)

	appProfile, _ := wl.GetApplicationProfile()
	appProfileJson, _ := json.Marshal(appProfile)

	networkNeighborhood, _ := wl.GetNetworkNeighborhood()
	networkNeighborhoodJson, _ := json.Marshal(networkNeighborhood)

	t.Logf("network neighborhood: %v", string(networkNeighborhoodJson))

	t.Logf("application profile: %v", string(appProfileJson))

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")                               // no alert expected
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "server")                              // alert expected
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server") // no alert expected
	_, _, err = wl.ExecIntoPod([]string{"curl", "ebpf.io", "-m", "2"}, "nginx")             // alert expected

	// Wait for the alert to be signaled
	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "server", []bool{true})
	testutils.AssertNotContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})

	testutils.AssertContains(t, alerts, "DNS Anomalies in container", "curl", "nginx", []bool{true})
	testutils.AssertNotContains(t, alerts, "DNS Anomalies in container", "wget", "server", []bool{true})

	// Verify UID fields are populated in alerts
	testutils.AssertUIDFieldsPopulated(t, alerts, wl.Namespace)

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
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfileCompletion(150)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// Wait for the alerts to be generated
	time.Sleep(2 * time.Minute)

	// Get all the alerts for the namespace
	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	// Validate that all alerts are signaled
	expectedAlerts := map[string]bool{
		"Unexpected process launched":               false,
		"Files Access Anomalies in container":       false,
		"Syscalls Anomalies in container":           false,
		"Linux Capabilities Anomalies in container": false,
		"Workload uses Kubernetes API unexpectedly": false,
		"Process executed from malicious source":    false,
		"Process tries to load a kernel module":     false,
		"Drifted process executed":                  false,
		"Process executed from mount":               false,
		"Unexpected service account token access":   false,
		"DNS Anomalies in container":                false,
		"Crypto Mining Related Port Communication":  false,
		"Crypto Mining Domain Communication":        false,
	}

	expectedFailOnProfile := map[string][]bool{
		"Unexpected process launched":               {true},
		"Files Access Anomalies in container":       {true},
		"Syscalls Anomalies in container":           {true},
		"Linux Capabilities Anomalies in container": {true},
		"Workload uses Kubernetes API unexpectedly": {true},
		"Process executed from malicious source":    {false},
		"Process tries to load a kernel module":     {false},
		"Drifted process executed":                  {true},
		"Process executed from mount":               {true},
		"Unexpected service account token access":   {true},
		"DNS Anomalies in container":                {true},
		"Crypto Mining Related Port Communication":  {true},
		"Crypto Mining Domain Communication":        {false},
	}

	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		failOnProfile, failOnProfileOk := alert.Labels["fail_on_profile"]
		failOnProfileBool, err := strconv.ParseBool(failOnProfile)
		require.NoError(t, err, "Error parsing fail_on_profile")
		if ruleOk && failOnProfileOk {
			if _, exists := expectedAlerts[ruleName]; exists && slices.Contains(expectedFailOnProfile[ruleName], failOnProfileBool) {
				expectedAlerts[ruleName] = true
			}
		}
	}

	for ruleName, signaled := range expectedAlerts {
		assert.Truef(t, signaled, "Expected alert '%s' was not signaled", ruleName)
	}
}

func Test_03_BasicLoadActivities(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// Create loader
	loader, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/locust-deployment.yaml"))
	require.NoError(t, err)
	err = loader.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	loadStart := time.Now()

	// Create a load of 5 minutes
	time.Sleep(5 * time.Minute)

	loadEnd := time.Now()

	// Get CPU usage of Node Agent pods
	podToCpuUsage, err := testutils.GetNodeAgentAverageCPUUsage(loadStart, loadEnd)
	require.NoError(t, err, "Error getting CPU usage")

	require.NotEqual(t, 0, podToCpuUsage, "No CPU usage data found")

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
		require.NoError(t, err, "Error creating deployment")
		workloads = append(workloads, *wl)
	}
	for _, wl := range workloads {
		err := wl.WaitForReady(80)
		require.NoError(t, err, "Error waiting for workload to be ready")
		err = wl.WaitForApplicationProfileCompletion(80)
		require.NoError(t, err, "Error waiting for application profile to be completed")
	}

	// Wait for 60 seconds for the GC to run, so the memory leak can be detected
	time.Sleep(60 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_basic", start, time.Now())
	require.NoError(t, err, "Error plotting memory usage")

	require.NotEqual(t, 0, metrics, "No memory usage data found")

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
	require.NoError(t, err, "Error creating workload")
	err = nginx.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	err = nginx.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to have a baseline memory usage")
	time.Sleep(300 * time.Second)

	//Exec into the nginx pod and create a file in the /tmp directory in a loop
	startLoad := time.Now()
	for i := 0; i < 100; i++ {
		_, _, err := nginx.ExecIntoPod([]string{"bash", "-c", "for i in {1..100}; do touch /tmp/nginx-test-$i; done"}, "")
		require.NoError(t, err, "Error executing remote command")
		if i%5 == 0 {
			t.Logf("Created file %d times", (i+1)*100)
		}
	}

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to GC to run")
	time.Sleep(300 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_10k_alerts", startLoad, time.Now())
	require.NoError(t, err, "Error plotting memory usage")

	require.NotEqual(t, 0, metrics, "No memory usage data found")

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
	require.NoError(t, err, "Error creating workload")
	err = nginx.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Give time for the nginx application profile to be ready
	require.NoError(t, nginx.WaitForApplicationProfile(80, "ready"))

	// Exec into the nginx pod and kill the process
	_, _, err = nginx.ExecIntoPod([]string{"bash", "-c", "kill -9 1"}, "")
	require.NoError(t, err, "Error executing remote command")

	// Wait for the application profile to be 'completed'
	err = nginx.WaitForApplicationProfileCompletion(20)
	require.NoError(t, err, "Error waiting for application profile to be completed")
}

func Test_07_RuleBindingApplyTest(t *testing.T) {
	ruleBindingPath := func(name string) string {
		return path.Join(utils.CurrentDir(), "resources/rulebindings", name)
	}

	// valid
	exitCode := testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", ruleBindingPath("all-valid.yaml"))
	assert.Equal(t, 0, exitCode, "Error applying valid rule binding")
	exitCode = testutils.RunCommand("kubectl", "delete", "-f", ruleBindingPath("all-valid.yaml"))
	require.Equal(t, 0, exitCode, "Error deleting valid rule binding")

	// duplicate fields
	file := ruleBindingPath("dup-fields-name-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-name-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-id-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", file)
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
	require.NoError(t, err)

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
	require.NoError(t, err)

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
	require.NoError(t, err, "Error creating services")

	t.Log("Creating deployments")
	deployments, err := testutils.CreateWorkloadsInPath(ns.Name, path.Join(utils.CurrentDir(), "resources/hipster_shop/deployments"))
	require.NoError(t, err, "Error creating deployments")

	t.Log("Waiting for all workloads to be ready")
	for _, wl := range deployments {
		err = wl.WaitForReady(80)
		require.NoError(t, err, "Error waiting for workload to be ready")
	}
	t.Log("All workloads are ready")

	t.Log("Waiting for all application profiles to be completed")
	for _, wl := range deployments {
		err = wl.WaitForApplicationProfileCompletion(80)
		require.NoError(t, err, "Error waiting for application profile to be completed")
	}

	// wait for 1 minute for the alerts to be generated
	time.Sleep(1 * time.Minute)

	require.NoError(t, err, "Error getting pods with restarts")

	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")

	assert.Equal(t, 0, len(alerts), "Expected no alerts to be generated, but got %d alerts", len(alerts))
}

func Test_10_MalwareDetectionTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	t.Log("Deploy container with malware")
	exitCode := testutils.RunCommand("kubectl", "run", "-n", ns.Name, "malware-cryptominer", "--image=quay.io/petr_ruzicka/malware-cryptominer-container:2.0.2")
	require.Equalf(t, 0, exitCode, "expected no error when deploying malware container")

	// Wait for pod to be ready
	exitCode = testutils.RunCommand("kubectl", "wait", "--for=condition=Ready", "pod", "malware-cryptominer", "-n", ns.Name, "--timeout=300s")
	require.Equalf(t, 0, exitCode, "expected no error when waiting for pod to be ready")

	// wait for application profile to be completed
	time.Sleep(3 * time.Minute)

	_, _, err := testutils.ExecIntoPod("malware-cryptominer", ns.Name, []string{"ls", "-l", "/usr/share/nginx/html/xmrig"}, "")
	require.NoErrorf(t, err, "expected no error when executing command in malware container")

	_, _, err = testutils.ExecIntoPod("malware-cryptominer", ns.Name, []string{"/usr/share/nginx/html/xmrig/xmrig"}, "")

	// wait for the alerts to be generated
	time.Sleep(20 * time.Second)

	alerts, err := testutils.GetMalwareAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")

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
	require.NoError(t, err, "Error creating workload")
	err = endpointTraffic.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	require.NoError(t, endpointTraffic.WaitForApplicationProfile(80, "ready"))

	// Merge methods
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80"}, "")
	require.NoError(t, err)
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80", "-O", "/dev/null", "--post-data", "test-data"}, "") // avoid index.html already exists error

	// Merge dynamic
	for i := 0; i < threshold; i++ {
		_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", fmt.Sprintf("http://127.0.0.1:80/users/%d", i)}, "")
	}

	// Merge headers
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80/users/99", "--header", "Connection:1234r"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80/users/12", "--header", "Connection:ziz"}, "")

	err = endpointTraffic.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	applicationProfile, err := endpointTraffic.GetApplicationProfile()
	require.NoError(t, err, "Error getting application profile")

	headers := map[string][]string{"Connection": {"close"}, "Host": {"127.0.0.1:80"}}
	rawJSON, err := json.Marshal(headers)
	require.NoError(t, err)

	endpoint2 := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/",
		Methods:   []string{"GET", "POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON,
	}

	headers = map[string][]string{"Host": {"127.0.0.1:80"}, "Connection": {"1234r", "close", "ziz"}}
	rawJSON, err = json.Marshal(headers)
	require.NoError(t, err)

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
		err := json.Unmarshal(headers, &headersMap)
		require.NoError(t, err, "Error unmarshalling headers")

		if headersMap["Connection"] != nil {
			sort.Strings(headersMap["Connection"])
			rawJSON, err = json.Marshal(headersMap)
			require.NoError(t, err)
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
		assert.Truef(t, found, "Expected endpoint %v not found in the application profile", expectedEndpoint)
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
	// require.NoError(t, wl.WaitForApplicationProfile(80, "ready"), "Application profile not ready")
	time.Sleep(10 * time.Second)

	// Generate initial profile data
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")
	require.NoError(t, err, "Failed to exec into nginx container")
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")
	require.NoError(t, err, "Failed to exec into server container")

	require.NoError(t, wl.WaitForApplicationProfileCompletion(160), "Profile failed to complete")
	time.Sleep(10 * time.Second) // Allow profile processing

	// Log initial profile state
	initialProfile, err := wl.GetApplicationProfile()
	require.NoError(t, err, "Failed to get initial profile")
	initialProfileJSON, _ := json.Marshal(initialProfile)
	t.Logf("Initial application profile:\n%s", string(initialProfileJSON))

	// PHASE 2: Verify initial alerts
	t.Log("Testing initial alert generation...")
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")  // Expected: no alert
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "server") // Expected: alert
	// time.Sleep(2 * time.Minute)                                // Wait for alert generation
	time.Sleep(30 * time.Second) // Wait for alert generation

	initialAlerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Failed to get initial alerts")

	// Record initial alert count
	initialAlertCount := 0
	for _, alert := range initialAlerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
			initialAlertCount++
		}
	}

	testutils.AssertContains(t, initialAlerts, "Unexpected process launched", "ls", "server", []bool{true})
	testutils.AssertNotContains(t, initialAlerts, "Unexpected process launched", "ls", "nginx", []bool{true, false})

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
	time.Sleep(1 * time.Minute) // Allow merge to complete

	// Test merged profile behavior
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")  // Expected: no alert
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "server") // Expected: no alert (user profile should suppress alert)
	time.Sleep(1 * time.Minute)                                // Wait for potential alerts

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

	// The new cache doesn't listen to patches
	// PHASE 5: Check PATCH (removing the ls command from the user profile of the server container and triggering an alert)
	// t.Log("Patching user profile to remove ls command from server container...")
	// patchOperations := []utils.PatchOperation{
	// 	{Op: "remove", Path: "/spec/containers/1/execs/0"},
	// }

	// patch, err := json.Marshal(patchOperations)
	// require.NoError(t, err, "Failed to marshal patch operations")

	// _, err = storageClient.ApplicationProfiles(ns.Name).Patch(context.Background(), userProfile.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
	// require.NoError(t, err, "Failed to patch user profile")

	// // Verify patched profile behavior
	// time.Sleep(15 * time.Second) // Allow merge to complete

	// // Log the profile that was patched
	// patchedProfile, err := wl.GetApplicationProfile()
	// require.NoError(t, err, "Failed to get patched profile")
	// t.Logf("Patched application profile:\n%v", patchedProfile)

	// // Test patched profile behavior
	// wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")  // Expected: no alert
	// wl.ExecIntoPod([]string{"ls", "-l"}, "server") // Expected: alert (ls command removed from user profile)
	// time.Sleep(10 * time.Second)                   // Wait for potential alerts

	// // Verify alert counts
	// finalAlerts, err = testutils.GetAlerts(wl.Namespace)
	// require.NoError(t, err, "Failed to get final alerts")

	// // Only count new alerts (after the initial count)
	// newAlertCount = 0
	// for _, alert := range finalAlerts {
	// 	if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
	// 		newAlertCount++
	// 	}
	// }

	// t.Logf("Alert counts - Initial: %d, Final: %d", initialAlertCount, newAlertCount)

	// if newAlertCount <= initialAlertCount {
	// 	t.Logf("Full alert details:")
	// 	for _, alert := range finalAlerts {
	// 		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
	// 			t.Logf("Alert: %+v", alert)
	// 		}
	// 	}
	// 	t.Errorf("New alerts were not generated after patch (Initial: %d, Final: %d)", initialAlertCount, newAlertCount)
	// }
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
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "DNS Anomalies in container" && alert.Labels["container_name"] == "server" {
			initialAlertCount++
		}
	}

	// Verify initial alerts
	testutils.AssertContains(t, initialAlerts, "DNS Anomalies in container", "wget", "server", []bool{true})
	testutils.AssertContains(t, initialAlerts, "DNS Anomalies in container", "curl", "nginx", []bool{true})

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
	time.Sleep(60 * time.Second) // Allow merge to complete

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
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "DNS Anomalies in container" && alert.Labels["container_name"] == "server" {
			newAlertCount++
		}
	}

	t.Logf("Alert counts - Initial: %d, After merge: %d", initialAlertCount, newAlertCount)

	if newAlertCount > initialAlertCount {
		t.Logf("Full alert details:")
		for _, alert := range mergedAlerts {
			if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "DNS Anomalies in container" && alert.Labels["container_name"] == "server" {
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

	time.Sleep(60 * time.Second) // Allow merge to complete

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
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "DNS Anomalies in container" && alert.Labels["container_name"] == "server" {
			finalAlertCount++
		}
	}

	t.Logf("Alert counts - Initial: %d, Final: %d", initialAlertCount, finalAlertCount)

	if finalAlertCount <= initialAlertCount {
		t.Logf("Full alert details:")
		for _, alert := range finalAlerts {
			if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "DNS Anomalies in container" && alert.Labels["container_name"] == "server" {
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
	time.Sleep(10 * time.Second)

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

	symlinkPolicy := applicationProfile.Spec.Containers[0].PolicyByRuleId["R1010"]
	assert.Equal(t, []string{"ln"}, symlinkPolicy.AllowedProcesses)

	hardlinkPolicy := applicationProfile.Spec.Containers[0].PolicyByRuleId["R1012"]
	assert.Len(t, hardlinkPolicy.AllowedProcesses, 0)

	fmt.Println("After completed....")

	// wait for cache
	time.Sleep(40 * time.Second)

	// generate hardlink alert
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "/etc/shadow", "/tmp/a"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// not generate alert
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "-s", "/etc/shadow", "/tmp/a"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// Wait for the alert to be signaled
	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(endpointTraffic.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	testutils.AssertContains(t, alerts, "Hard link created over sensitive file", "ln", "endpoint-traffic", []bool{true})
	testutils.AssertNotContains(t, alerts, "Soft link created over sensitive file", "ln", "endpoint-traffic", []bool{true})

	// Also check for learning mode
	testutils.AssertContains(t, alerts, "Soft link created over sensitive file", "ln", "endpoint-traffic", []bool{false})
	testutils.AssertNotContains(t, alerts, "Hard link created over sensitive file", "ln", "endpoint-traffic", []bool{false})

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
				helpersv1.CompletionMetadataKey: helpersv1.Full,
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
			Value: helpersv1.Learning,
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
	require.NoError(t, err, "Error creating workload")

	require.NoError(t, wl.WaitForReady(80))

	time.Sleep(30 * time.Second)

	_, _, _ = wl.ExecIntoPod([]string{"service", "nginx", "stop"}, "") // suppose to get error
	// wl, err = testutils.NewTestWorkloadFromK8sIdentifiers(ns.Name, wl.UnstructuredObj.GroupVersionKind().Kind, "nginx-deployment")
	// require.NoError(t, err, "Error re-fetching workload after stop")
	// require.NoError(t, wl.WaitForReady(80))
	// require.NoError(t, wl.WaitForApplicationProfileCompletion(160))

	time.Sleep(160 * time.Second)

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err)

	// Wait for the alert to be generated
	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

func Test_17_ApCompletedToPartialUpdateTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	time.Sleep(30 * time.Second)
	require.NoError(t, wl.WaitForReady(80))
	require.NoError(t, wl.WaitForNetworkNeighborhood(80, "ready"))

	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Error restarting daemonset")

	require.NoError(t, wl.WaitForApplicationProfileCompletion(160))
	require.NoError(t, wl.WaitForNetworkNeighborhoodCompletion(160))

	time.Sleep(30 * time.Second)

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err)

	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

func Test_18_ShortLivedJobTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	// Create a short-lived job
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/echo-job.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Application profile should be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")
}

func Test_19_AlertOnPartialProfileTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Error restarting daemonset")

	// Wait for the application profile to be completed
	err = wl.WaitForApplicationProfileCompletion(160)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	profile, err := wl.GetApplicationProfile()
	require.NoError(t, err, "Error getting application profile")

	require.Equal(t, helpersv1.Partial, profile.Annotations[helpersv1.CompletionMetadataKey])

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by executing a command
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err, "Error executing command in pod")
	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

func Test_20_AlertOnPartialThenLearnProcessTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Error restarting daemonset")

	// Wait for the application profile to be completed (partial)
	err = wl.WaitForApplicationProfileCompletion(160)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by executing a command (should trigger alert on partial profile)
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err, "Error executing command in pod")

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})

	profile, err := wl.GetApplicationProfile()
	require.NoError(t, err, "Error getting application profile")

	// Restart the deployment to reset the profile learning
	err = testutils.RestartDeployment(ns.Name, wl.WorkloadObj.GetName())
	require.NoError(t, err, "Error restarting deployment")

	wl, err = testutils.NewTestWorkloadFromK8sIdentifiers(ns.Name, wl.UnstructuredObj.GroupVersionKind().Kind, "nginx-deployment")
	require.NoError(t, err, "Error re-fetching workload after restart")

	// Wait for the workload to be ready after restart
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready after restart")

	// Execute the same command during learning phase (should be learned in profile)
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err, "Error executing command in pod during learning")

	// Wait for the application profile to be completed (with ls command learned)
	err = wl.WaitForApplicationProfileCompletionWithBlacklist(160, []string{profile.Name})
	require.NoError(t, err, "Error waiting for application profile to be completed after learning")

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Execute the same command again - should NOT trigger an alert now
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err, "Error executing command in pod after learning")

	// Wait to see if any alert is generated
	time.Sleep(15 * time.Second)
	alertsAfter, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts after learning")

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
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Error restarting daemonset")

	// Wait for the network neighborhood to be completed (partial)
	err = wl.WaitForNetworkNeighborhoodCompletion(160)
	require.NoError(t, err, "Error waiting for network neighborhood to be completed")

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by making a network request (should trigger alert on partial profile)
	// Using curl with timeout and targeting nginx container (same as Test_22)
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	require.NoError(t, err, "Error executing network command in pod")

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")
	testutils.AssertContains(t, alerts, "DNS Anomalies in container", "curl", "nginx", []bool{true})

	nn, err := wl.GetNetworkNeighborhood()
	require.NoError(t, err, "Error getting network neighborhood")

	// Restart the deployment to reset the profile learning
	err = testutils.RestartDeployment(ns.Name, wl.WorkloadObj.GetName())
	require.NoError(t, err, "Error restarting deployment")

	// Print we restarted the deployment
	logger.L().Info("restarted deployment", helpers.String("name", wl.WorkloadObj.GetName()), helpers.String("namespace", wl.WorkloadObj.GetNamespace()))

	// Sleep to allow the restart to complete
	time.Sleep(30 * time.Second)

	wl, err = testutils.NewTestWorkloadFromK8sIdentifiers(ns.Name, wl.UnstructuredObj.GroupVersionKind().Kind, "multiple-containers-deployment")
	require.NoError(t, err, "Error re-fetching workload after restart")

	// Wait for the workload to be ready after restart
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready after restart")

	// Execute the same network command during learning phase (should be learned in profile)
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	require.NoError(t, err, "Error executing network command in pod during learning")

	// Print the workload details we are using
	logger.L().Info("workload details", helpers.String("name", wl.WorkloadObj.GetName()), helpers.String("namespace", wl.WorkloadObj.GetNamespace()))
	// Print the metadata of the workload
	logger.L().Info("workload metadata", helpers.Interface("metadata", wl.WorkloadObj.GetAnnotations()), helpers.Interface("labels", wl.WorkloadObj.GetLabels()))

	// Wait for the network neighborhood to be completed (with curl command learned)
	err = wl.WaitForNetworkNeighborhoodCompletionWithBlacklist(160, []string{nn.Name})
	require.NoError(t, err, "Error waiting for network neighborhood to be completed after learning")

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Execute the same network command again - should NOT trigger an alert now
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	require.NoError(t, err, "Error executing network command in pod after learning")

	// Wait to see if any alert is generated
	time.Sleep(15 * time.Second)
	alertsAfter, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts after learning")

	// Should not contain new alert for curl command after learning
	count := 0
	for _, alert := range alertsAfter {
		if alert.Labels["rule_name"] == "DNS Anomalies in container" && alert.Labels["container_name"] == "nginx" && alert.Labels["process_name"] == "curl" {
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
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Failed to restart daemonset")

	// Wait for the network neighborhood to be completed
	err = wl.WaitForNetworkNeighborhoodCompletion(160)
	require.NoError(t, err, "Error waiting for network neighborhood to be completed")

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by making an unexpected network request
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	require.NoError(t, err, "Error executing network command in pod")

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")
	testutils.AssertContains(t, alerts, "DNS Anomalies in container", "curl", "nginx", []bool{true})
}

func Test_23_RuleCooldownTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	require.NoError(t, wl.WaitForApplicationProfileCompletion(80))

	// Wait for cache
	time.Sleep(30 * time.Second)

	// Run the same process 20 times
	for i := 0; i < 20; i++ {
		_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
		require.NoError(t, err)
		time.Sleep(1 * time.Second)
	}

	// Wait for alerts to be processed
	time.Sleep(30 * time.Second)

	// Get all alerts
	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	// Count alerts for "Unexpected process launched" rule
	alertCount := 0
	for _, alert := range alerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
			alertCount++
		}
	}

	// We should get exactly 10 alerts (cooldown threshold) even though we ran the process 20 times
	assert.Equal(t, 10, alertCount, "Expected exactly 10 alerts due to cooldown threshold, got %d", alertCount)

	// Verify the specific alert details
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

func Test_24_ProcessTreeDepthTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	endpointTraffic, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/tree.yaml"))
	require.NoError(t, err, "Error creating workload")

	err = endpointTraffic.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	err = endpointTraffic.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// wait for cache
	time.Sleep(30 * time.Second)

	// Add to rule policy symlink
	buf, _, err := endpointTraffic.ExecIntoPod([]string{"/bin/sh", "-c", "python3 /root/python_spawner.py 10"}, "")
	require.NoError(t, err)

	t.Logf("Output: %s", buf)

	t.Logf("Waiting for the alert to be signaled")

	// Wait for the alert to be signaled
	time.Sleep(2 * time.Minute)

	alerts, err := testutils.GetAlerts(endpointTraffic.Namespace)
	require.NoError(t, err, "Error getting alerts")

	found := false

	for _, alert := range alerts {
		if alert.Labels["rule_name"] == "Unexpected process launched" {
			if alert.Labels["processtree_depth"] == "10" {
				found = true
				break
			}
		}
	}

	assert.Truef(t, found, "Expected to find an alert for the process tree depth")

	t.Logf("Found alerts for the process tree depth: %v", alerts)
}

// Test_27_ApplicationProfileOpens tests that the dynamic path matching in
// application profiles works correctly for both recorded (auto-learned)
// profiles and user-defined profiles.
//
// Path matching symbols:
//
//	⋯  (U+22EF DynamicIdentifier)  — matches exactly ONE path segment
//	*  (WildcardIdentifier)         — matches ZERO or more path segments
//	0  (in endpoints)               — wildcard port (any port)
//
// R0002 "Files Access Anomalies in container" fires when a file is opened
// under a monitored prefix (/etc/, /var/log/, …) and the path was NOT
// recorded in the application profile.
func Test_27_ApplicationProfileOpens(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const ruleName = "Files Access Anomalies in container"
	const profileName = "nginx-regex-profile"

	// --- result tracking for end-of-test summary ---
	type subtestResult struct {
		name        string
		profilePath string
		filePath    string
		expectAlert bool
		passed      bool
		detail      string
	}
	var results []subtestResult
	addResult := func(name, profilePath, filePath string, expectAlert, passed bool, detail string) {
		results = append(results, subtestResult{name, profilePath, filePath, expectAlert, passed, detail})
	}
	defer func() {
		t.Log("\n========== Test_27 Summary ==========")
		anyFailed := false
		for _, r := range results {
			status := "PASS"
			if !r.passed {
				status = "FAIL"
				anyFailed = true
			}
			expect := "expect alert"
			if !r.expectAlert {
				expect = "expect NO alert"
			}
			t.Logf("  [%s] %-35s profile=%-25s file=%-25s %s", status, r.name, r.profilePath, r.filePath, expect)
			if !r.passed {
				t.Logf("         -> %s", r.detail)
			}
		}
		if !anyFailed {
			t.Log("  All subtests passed.")
		}
		t.Log("======================================")
	}()

	// deployWithProfile creates a user-defined ApplicationProfile with the
	// given Opens list, deploys nginx with the kubescape.io/user-defined-profile
	// label pointing at it, and waits for the pod + cache to be ready.
	deployWithProfile := func(t *testing.T, opens []v1beta1.OpenCalls) *testutils.TestWorkload {
		t.Helper()
		ns := testutils.NewRandomNamespace()

		profile := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      profileName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ApplicationProfileSpec{
				Architectures: []string{"amd64"},
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "nginx",
						Execs: []v1beta1.ExecCalls{
							{Path: "/bin/cat", Args: []string{"/bin/cat"}},
						},
						Opens: opens,
					},
				},
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.ApplicationProfiles(ns.Name).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined profile %q in ns %s", profileName, ns.Name)

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-profile-deployment.yaml"))
		require.NoError(t, err, "create workload in ns %s", ns.Name)
		require.NoError(t, wl.WaitForReady(80), "workload not ready in ns %s", ns.Name)

		time.Sleep(20 * time.Second) // let node-agent pick up the profile
		return wl
	}

	// triggerAndGetAlerts execs cat on the given path and returns the alerts.
	triggerAndGetAlerts := func(t *testing.T, wl *testutils.TestWorkload, filePath string) []testutils.Alert {
		t.Helper()
		stdout, stderr, err := wl.ExecIntoPod([]string{"cat", filePath}, "nginx")
		if err != nil {
			t.Errorf("exec 'cat %s' in container nginx failed: %v (stdout=%q stderr=%q)", filePath, err, stdout, stderr)
		}
		time.Sleep(30 * time.Second)
		alerts, err := testutils.GetAlerts(wl.Namespace)
		require.NoError(t, err, "get alerts from ns %s", wl.Namespace)
		return alerts
	}

	// hasAlert checks whether an R0002 alert exists for comm=cat, container=nginx.
	hasAlert := func(alerts []testutils.Alert) bool {
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName &&
				a.Labels["comm"] == "cat" &&
				a.Labels["container_name"] == "nginx" {
				return true
			}
		}
		return false
	}

	// ---------------------------------------------------------------
	// 1a. Recorded (auto-learned) profile must use absolute paths.
	//     There must be no "." in the Opens paths.
	// ---------------------------------------------------------------
	t.Run("recorded_profile_absolute_paths", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
		require.NoError(t, err)
		require.NoError(t, wl.WaitForReady(80))
		require.NoError(t, wl.WaitForApplicationProfileCompletion(80))

		profile, err := wl.GetApplicationProfile()
		require.NoError(t, err, "get application profile")

		passed := true
		for _, container := range profile.Spec.Containers {
			for _, open := range container.Opens {
				if !strings.HasPrefix(open.Path, "/") {
					t.Errorf("recorded path must be absolute: got %q (container %s)", open.Path, container.Name)
					passed = false
				}
				if open.Path == "." {
					t.Errorf("recorded path must not be relative dot: got %q (container %s)", open.Path, container.Name)
					passed = false
				}
			}
		}
		detail := ""
		if !passed {
			detail = "found non-absolute or '.' paths in recorded profile"
		}
		addResult("recorded_profile_absolute_paths", "(auto-learned)", "(nginx startup)", false, passed, detail)
	})

	// ---------------------------------------------------------------
	// 1b. User-defined profile wildcard tests.
	//     Each sub-test deploys nginx in its own namespace with a
	//     different Opens pattern and verifies R0002 behaviour.
	// ---------------------------------------------------------------

	// 1b-1: Exact path — profile has the exact file => no alert.
	t.Run("exact_path_match", func(t *testing.T) {
		profilePath := "/etc/nginx/nginx.conf"
		filePath := "/etc/nginx/nginx.conf"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
			{Path: "/etc/ld.so.cache", Flags: []string{"O_RDONLY", "O_CLOEXEC"}}, // dynamic linker opens this on every exec
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if got {
			t.Errorf("expected NO R0002 alert: profile allows %q, opened %q, but alert fired", profilePath, filePath)
		}
		addResult("exact_path_match", profilePath, filePath, false, !got,
			fmt.Sprintf("got %d alerts, expected none for cat", len(alerts)))
	})

	// 1b-2: Exact path — profile has a DIFFERENT file => alert.
	t.Run("exact_path_mismatch", func(t *testing.T) {
		profilePath := "/etc/nginx/nginx.conf"
		filePath := "/etc/hostname"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if !got {
			t.Errorf("expected R0002 alert: profile only allows %q, opened %q, but no alert", profilePath, filePath)
		}
		addResult("exact_path_mismatch", profilePath, filePath, true, got,
			fmt.Sprintf("got %d alerts, expected at least one for cat", len(alerts)))
	})

	// 1b-3: Ellipsis ⋯ matches single segment — /etc/⋯ covers /etc/hostname.
	t.Run("ellipsis_single_segment_match", func(t *testing.T) {
		profilePath := "/etc/" + dynamicpathdetector.DynamicIdentifier
		filePath := "/etc/hostname"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if got {
			t.Errorf("expected NO R0002 alert: profile %q should match %q (single segment), but alert fired", profilePath, filePath)
		}
		addResult("ellipsis_single_segment_match", profilePath, filePath, false, !got,
			fmt.Sprintf("got %d alerts, expected none for cat", len(alerts)))
	})

	// 1b-4: Ellipsis ⋯ rejects multi-segment — /etc/⋯ does NOT cover
	//        /etc/nginx/nginx.conf (two segments past /etc/).
	t.Run("ellipsis_rejects_multi_segment", func(t *testing.T) {
		profilePath := "/etc/" + dynamicpathdetector.DynamicIdentifier
		filePath := "/etc/nginx/nginx.conf"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if !got {
			t.Errorf("expected R0002 alert: profile %q should NOT match %q (two segments), but no alert", profilePath, filePath)
		}
		addResult("ellipsis_rejects_multi_segment", profilePath, filePath, true, got,
			fmt.Sprintf("got %d alerts, expected at least one for cat", len(alerts)))
	})

	// 1b-5: Wildcard * matches any depth — /etc/* covers /etc/nginx/nginx.conf.
	t.Run("wildcard_matches_deep_path", func(t *testing.T) {
		profilePath := "/etc/*"
		filePath := "/etc/nginx/nginx.conf"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if got {
			t.Errorf("expected NO R0002 alert: profile %q should match %q (wildcard), but alert fired", profilePath, filePath)
		}
		addResult("wildcard_matches_deep_path", profilePath, filePath, false, !got,
			fmt.Sprintf("got %d alerts, expected none for cat", len(alerts)))
	})
}

// Test_28_UserDefinedNetworkNeighborhood exercises the user-defined
// NetworkNeighborhood label (kubescape.io/user-defined-network), both
// standalone and in combination with the user-defined ApplicationProfile
// label (kubescape.io/user-defined-profile).
//
// Subtests:
//
//	a. both_defined_allowed_activity   — AP + NN provided; allowed exec+DNS → no alerts
//	b. both_defined_unknown_exec       — AP + NN provided; unknown exec → R0001
//	c. both_defined_unknown_dns        — AP + NN provided; unknown DNS → R0005
//	d. nn_only_allowed_dns             — only NN provided; allowed DNS → no R0005
//	e. nn_only_unknown_dns             — only NN provided; unknown DNS → R0005
func Test_28_UserDefinedNetworkNeighborhood(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const (
		execRuleName = "Unexpected process launched"
		dnsRuleName  = "DNS Anomalies in container"
		openRuleName = "Files Access Anomalies in container"

		profileName = "fusioncore-profile"
		networkName = "fusioncore-network"

		allowedDomain = "fusioncore.ai"
		unknownDomain = "evil.example.com"

		// How long to let node-agent ingest user-defined resources before exec.
		ingestWait = 10 * time.Second
		// How long to let alerts propagate after exec.
		alertWait = 10 * time.Second
	)

	// ----------------------------------------------------------------
	// Shared helper: create user-defined ApplicationProfile resource.
	// ----------------------------------------------------------------
	createProfile := func(t *testing.T, ns, name string) {
		t.Helper()
		t.Logf("[%s] creating ApplicationProfile %q in namespace %q", t.Name(), name, ns)
		profile := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
			Spec: v1beta1.ApplicationProfileSpec{
				Architectures: []string{"amd64"},
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name:     "curl",
						ImageID:  "docker.io/curlimages/curl@sha256:08e466006f0860e54fc299378de998935333e0e130a15f6f98482e9f8dab3058",
						ImageTag: "docker.io/curlimages/curl:8.5.0",
						Capabilities: []string{
							"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
							"CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_ADMIN",
						},
						Execs: []v1beta1.ExecCalls{
							{Path: "/bin/sleep", Args: []string{"/bin/sleep", "infinity"}},
							{Path: "/bin/cat", Args: []string{"/bin/cat"}},
							{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "-sm2", "fusioncore.ai"}},
						},
						Opens: []v1beta1.OpenCalls{
							{Path: "/etc/hosts", Flags: []string{"O_CLOEXEC", "O_RDONLY", "O_LARGEFILE"}},
							{Path: "/etc/ld-musl-x86_64.path", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/etc/passwd", Flags: []string{"O_RDONLY", "O_CLOEXEC", "O_LARGEFILE"}},
							{Path: "/etc/resolv.conf", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/etc/ssl/openssl.cnf", Flags: []string{"O_RDONLY", "O_LARGEFILE"}},
							{Path: "/lib/libcurl.so.4", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/lib/libcrypto.so.3", Flags: []string{"O_CLOEXEC", "O_RDONLY", "O_LARGEFILE"}},
							{Path: "/lib/libssl.so.3", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/lib/libz.so.1.3", Flags: []string{"O_LARGEFILE", "O_CLOEXEC", "O_RDONLY"}},
						},
						Syscalls: []string{
							"arch_prctl", "bind", "brk", "capget", "capset", "chdir",
							"clone", "close", "close_range", "connect", "epoll_ctl",
							"epoll_pwait", "execve", "exit", "exit_group", "faccessat2",
							"fchown", "fcntl", "fstat", "fstatfs", "futex", "getcwd",
							"getdents64", "getegid", "geteuid", "getgid", "getpeername",
							"getppid", "getsockname", "getsockopt", "gettid", "getuid",
							"ioctl", "membarrier", "mmap", "mprotect", "munmap",
							"nanosleep", "newfstatat", "open", "openat", "openat2",
							"pipe", "poll", "prctl", "read", "recvfrom", "recvmsg",
							"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sendto",
							"set_tid_address", "setgid", "setgroups", "setsockopt",
							"setuid", "sigaltstack", "socket", "statx", "tkill",
							"unknown", "write", "writev",
						},
					},
				},
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.ApplicationProfiles(ns).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined application profile in ns %s", ns)
		t.Logf("[%s] ApplicationProfile %q created successfully", t.Name(), name)
	}

	// ----------------------------------------------------------------
	// Shared helper: create user-defined NetworkNeighborhood resource.
	// Deliberately has NO "kubescape.io/managed-by: User" annotation —
	// the user-defined-network label on the pod is the sole linkage.
	// ----------------------------------------------------------------
	createNetwork := func(t *testing.T, ns string) {
		t.Helper()
		t.Logf("[%s] creating NetworkNeighborhood %q in namespace %q", t.Name(), networkName, ns)
		nn := &v1beta1.NetworkNeighborhood{
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkName,
				Namespace: ns,
			},
			Spec: v1beta1.NetworkNeighborhoodSpec{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "curl-fusioncore",
					},
				},
				Containers: []v1beta1.NetworkNeighborhoodContainer{
					{
						Name: "curl",
						Egress: []v1beta1.NetworkNeighbor{
							{
								Identifier: "kube-dns",
								Type:       "internal",
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"kubernetes.io/metadata.name": "kube-system",
									},
								},
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k8s-app": "kube-dns",
									},
								},
								Ports: []v1beta1.NetworkPort{
									{
										Name:     "UDP-53",
										Protocol: "UDP",
										Port:     ptr.To(int32(53)),
									},
								},
							},
							{
								Identifier: "fusioncore-ai",
								Type:       "external",
								DNS:        "fusioncore.ai.",
								DNSNames:   []string{"fusioncore.ai."},
								IPAddress:  "162.0.217.171",
								Ports: []v1beta1.NetworkPort{
									{
										Name:     "TCP-80",
										Protocol: "TCP",
										Port:     ptr.To(int32(80)),
									},
								},
							},
						},
					},
				},
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.NetworkNeighborhoods(ns).Create(
			context.Background(), nn, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined network neighborhood in ns %s", ns)
		t.Logf("[%s] NetworkNeighborhood %q created successfully", t.Name(), networkName)
	}

	// ----------------------------------------------------------------
	// Shared helper: deploy workload, wait for ready, log pod name.
	// Resources (AP and/or NN) must be created BEFORE the deployment so
	// the node-agent picks them up on first container add.
	// ----------------------------------------------------------------
	deployAndWait := func(t *testing.T, ns, yamlFile string) *testutils.TestWorkload {
		t.Helper()
		yamlPath := path.Join(utils.CurrentDir(), "resources/"+yamlFile)
		t.Logf("[%s] deploying workload from %s into namespace %q", t.Name(), yamlFile, ns)
		wl, err := testutils.NewTestWorkload(ns, yamlPath)
		require.NoError(t, err, "create workload in ns %s", ns)
		t.Logf("[%s] workload created, waiting for pods to be ready...", t.Name())
		require.NoError(t, wl.WaitForReady(80), "workload not ready in ns %s", ns)
		pods, podErr := wl.GetPods()
		if podErr == nil && len(pods) > 0 {
			t.Logf("[%s] pod ready: %s (namespace=%s)", t.Name(), pods[0].Name, ns)
		} else {
			t.Logf("[%s] pods ready but could not list them: %v", t.Name(), podErr)
		}
		return wl
	}

	// ----------------------------------------------------------------
	// Shared helper: exec into pod and log everything.
	// ----------------------------------------------------------------
	execAndLog := func(t *testing.T, wl *testutils.TestWorkload, cmd []string, container string) (string, string, error) {
		t.Helper()
		t.Logf("[%s] exec into pod: %v (container=%s)", t.Name(), cmd, container)
		stdout, stderr, err := wl.ExecIntoPod(cmd, container)
		if err != nil {
			t.Logf("[%s] exec error: %v", t.Name(), err)
		}
		if stdout != "" {
			t.Logf("[%s] exec stdout: %s", t.Name(), stdout)
		}
		if stderr != "" {
			t.Logf("[%s] exec stderr: %s", t.Name(), stderr)
		}
		if stdout == "" && stderr == "" && err == nil {
			t.Logf("[%s] exec completed with no output", t.Name())
		}
		return stdout, stderr, err
	}

	// ----------------------------------------------------------------
	// Shared helper: fetch and log alerts.
	// ----------------------------------------------------------------
	fetchAlerts := func(t *testing.T, ns string) []testutils.Alert {
		t.Helper()
		t.Logf("[%s] fetching alerts for namespace %q", t.Name(), ns)
		alerts, err := testutils.GetAlerts(ns)
		require.NoError(t, err, "get alerts for ns %s", ns)
		t.Logf("[%s] total alerts in namespace: %d", t.Name(), len(alerts))
		for i, a := range alerts {
			t.Logf("[%s]   alert[%d]: rule=%s container=%s labels=%v",
				t.Name(), i, a.Labels["rule_name"], a.Labels["container_name"], a.Labels)
		}
		return alerts
	}

	// ----------------------------------------------------------------
	// Shared helper: count alerts by rule+container.
	// ----------------------------------------------------------------
	countAlerts := func(alerts []testutils.Alert, ruleName, containerName string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName && a.Labels["container_name"] == containerName {
				n++
			}
		}
		return n
	}

	// =================================================================
	// a. Both AP + NN user-defined — allowed activity → no alerts.
	// =================================================================
	t.Run("both_defined_allowed_activity", func(t *testing.T) {
		t.Logf("[%s] START — both AP+NN user-defined, allowed activity, expect NO alerts", t.Name())
		ns := testutils.NewRandomNamespace()
		t.Logf("[%s] namespace created: %s", t.Name(), ns.Name)

		createProfile(t, ns.Name, profileName)
		createNetwork(t, ns.Name)
		wl := deployAndWait(t, ns.Name, "curl-both-user-defined-deployment.yaml")

		t.Logf("[%s] waiting %v for node-agent to ingest user-defined resources", t.Name(), ingestWait)
		time.Sleep(ingestWait)

		// Exec allowed commands: cat (in profile) and curl an allowed domain (in NN).
		execAndLog(t, wl, []string{"cat", "/etc/hosts"}, "curl")
		execAndLog(t, wl, []string{"curl", "-sm2", allowedDomain}, "curl")

		t.Logf("[%s] waiting %v for alerts to propagate", t.Name(), alertWait)
		time.Sleep(alertWait)

		alerts := fetchAlerts(t, wl.Namespace)

		execCount := countAlerts(alerts, execRuleName, "curl")
		openCount := countAlerts(alerts, openRuleName, "curl")
		dnsCount := countAlerts(alerts, dnsRuleName, "curl")

		t.Logf("[%s] result: exec=%d open=%d dns=%d", t.Name(), execCount, openCount, dnsCount)
		if execCount > 0 {
			t.Errorf("expected no R0001 alert for allowed exec, got %d", execCount)
		}
		if openCount > 0 {
			t.Errorf("expected no R0002 alert for allowed open, got %d", openCount)
		}
		if dnsCount > 0 {
			t.Errorf("expected no R0005 alert for allowed DNS, got %d", dnsCount)
		}
		t.Logf("[%s] DONE", t.Name())
	})

	// =================================================================
	// b. Both AP + NN user-defined — unknown exec → R0001 alert.
	// =================================================================
	t.Run("both_defined_unknown_exec", func(t *testing.T) {
		t.Logf("[%s] START — both AP+NN user-defined, unknown exec (ls), expect R0001", t.Name())
		ns := testutils.NewRandomNamespace()
		t.Logf("[%s] namespace created: %s", t.Name(), ns.Name)

		createProfile(t, ns.Name, profileName)
		createNetwork(t, ns.Name)
		wl := deployAndWait(t, ns.Name, "curl-both-user-defined-deployment.yaml")

		t.Logf("[%s] waiting %v for node-agent to ingest user-defined resources", t.Name(), ingestWait)
		time.Sleep(ingestWait)

		// ls is not in the user-defined AP → should trigger R0001.
		execAndLog(t, wl, []string{"ls", "/"}, "curl")

		t.Logf("[%s] waiting %v for alerts to propagate", t.Name(), alertWait)
		time.Sleep(alertWait)

		alerts := fetchAlerts(t, wl.Namespace)

		execCount := countAlerts(alerts, execRuleName, "curl")
		t.Logf("[%s] result: R0001=%d", t.Name(), execCount)
		if execCount == 0 {
			t.Errorf("expected R0001 alert for 'ls' (not in user-defined AP), got none")
		}
		t.Logf("[%s] DONE", t.Name())
	})

	// =================================================================
	// c. Both AP + NN user-defined — unknown DNS → R0005 alert.
	// =================================================================
	t.Run("both_defined_unknown_dns", func(t *testing.T) {
		t.Logf("[%s] START — both AP+NN user-defined, unknown DNS (%s), expect R0005", t.Name(), unknownDomain)
		ns := testutils.NewRandomNamespace()
		t.Logf("[%s] namespace created: %s", t.Name(), ns.Name)

		createProfile(t, ns.Name, profileName)
		createNetwork(t, ns.Name)
		wl := deployAndWait(t, ns.Name, "curl-both-user-defined-deployment.yaml")

		t.Logf("[%s] waiting %v for node-agent to ingest user-defined resources", t.Name(), ingestWait)
		time.Sleep(ingestWait)

		// evil.example.com is not in the user-defined NN → R0005.
		execAndLog(t, wl, []string{"curl", "-sm2", unknownDomain}, "curl")

		t.Logf("[%s] waiting %v for alerts to propagate", t.Name(), alertWait)
		time.Sleep(alertWait)

		alerts := fetchAlerts(t, wl.Namespace)

		dnsCount := countAlerts(alerts, dnsRuleName, "curl")
		t.Logf("[%s] result: R0005=%d", t.Name(), dnsCount)
		if dnsCount == 0 {
			t.Errorf("expected R0005 alert for %q (not in user-defined NN), got none", unknownDomain)
		}
		t.Logf("[%s] DONE", t.Name())
	})

	// =================================================================
	// d. Only NN user-defined (no AP label) — allowed DNS → no R0005.
	//    AP auto-learns normally.
	// =================================================================
	t.Run("nn_only_allowed_dns", func(t *testing.T) {
		t.Logf("[%s] START — NN-only user-defined, allowed DNS (%s), expect NO R0005", t.Name(), allowedDomain)
		ns := testutils.NewRandomNamespace()
		t.Logf("[%s] namespace created: %s", t.Name(), ns.Name)

		createNetwork(t, ns.Name)
		wl := deployAndWait(t, ns.Name, "curl-user-network-deployment.yaml")

		// Wait for auto-learned AP to complete (NN is user-defined, AP is learned).
		t.Logf("[%s] waiting for ApplicationProfile to auto-learn and complete...", t.Name())
		require.NoError(t, wl.WaitForApplicationProfileCompletion(80),
			"application profile failed to complete")
		t.Logf("[%s] ApplicationProfile completed", t.Name())

		// fusioncore.ai is in the user-defined NN → no R0005.
		execAndLog(t, wl, []string{"curl", "-sm2", allowedDomain}, "curl")

		t.Logf("[%s] waiting %v for alerts to propagate", t.Name(), alertWait)
		time.Sleep(alertWait)

		alerts := fetchAlerts(t, wl.Namespace)

		dnsCount := countAlerts(alerts, dnsRuleName, "curl")
		t.Logf("[%s] result: R0005=%d", t.Name(), dnsCount)
		if dnsCount > 0 {
			t.Errorf("expected no R0005 alert for %q (in user-defined NN), got %d", allowedDomain, dnsCount)
		}
		t.Logf("[%s] DONE", t.Name())
	})

	// =================================================================
	// e. Only NN user-defined (no AP label) — unknown DNS → R0005.
	// =================================================================
	t.Run("nn_only_unknown_dns", func(t *testing.T) {
		t.Logf("[%s] START — NN-only user-defined, unknown DNS (%s), expect R0005", t.Name(), unknownDomain)
		ns := testutils.NewRandomNamespace()
		t.Logf("[%s] namespace created: %s", t.Name(), ns.Name)

		createNetwork(t, ns.Name)
		wl := deployAndWait(t, ns.Name, "curl-user-network-deployment.yaml")

		t.Logf("[%s] waiting for ApplicationProfile to auto-learn and complete...", t.Name())
		require.NoError(t, wl.WaitForApplicationProfileCompletion(80),
			"application profile failed to complete")
		t.Logf("[%s] ApplicationProfile completed", t.Name())

		execAndLog(t, wl, []string{"curl", "-sm2", unknownDomain}, "curl")

		t.Logf("[%s] waiting %v for alerts to propagate", t.Name(), alertWait)
		time.Sleep(alertWait)

		alerts := fetchAlerts(t, wl.Namespace)

		dnsCount := countAlerts(alerts, dnsRuleName, "curl")
		t.Logf("[%s] result: R0005=%d", t.Name(), dnsCount)
		if dnsCount == 0 {
			t.Errorf("expected R0005 alert for %q (not in user-defined NN), got none", unknownDomain)
		}
		t.Logf("[%s] DONE", t.Name())
	})

}
