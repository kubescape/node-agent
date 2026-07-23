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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
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

// enableR0002ForTest applies an override Rules CRD that enables R0002 ("Files
// Access Anomalies in container") — which ships disabled in the bundle
// (rulelibrary default) — for the calling test's cluster only, without
// modifying tests/chart/templates/node-agent/default-rules.yaml. The
// rules-watcher filters disabled rules before its per-ID merge, so it uses this
// enabled copy in place of the disabled bundle one. Each component-test matrix
// job runs on its own cluster, so this stays isolated. Use as:
//
//	defer enableR0002ForTest(t)()
func enableR0002ForTest(t *testing.T) func() {
	t.Helper()
	override := path.Join(utils.CurrentDir(), "resources/r0002-files-access-enabled.yaml")
	require.Equal(t, 0, testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", override), "enable R0002 override")
	// allow the rules-watcher to pick up the newly enabled rule
	time.Sleep(10 * time.Second)
	return func() { testutils.RunCommand("kubectl", "delete", "--ignore-not-found", "-f", override) }
}

func Test_02_AllAlertsFromMaliciousApp(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)
	defer enableR0002ForTest(t)()

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
		"Process Executed from /dev/shm":            false,
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
		"Process Executed from /dev/shm":            {false},
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

	// Wait for dedup cache entries to expire (~2s TTL) so the next requests
	// with different headers are not deduplicated before reaching the profile.
	time.Sleep(3 * time.Second)

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

	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token >/dev/null"}, "")
	require.NoError(t, err)

	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	testutils.AssertContains(t, alerts, "Unexpected service account token access", "cat", "nginx", []bool{true})
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
	defer enableR0002ForTest(t)()

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
	// given Opens list, polls until it is retrievable from storage, then
	// deploys nginx with the kubescape.io/user-defined-profile label
	// pointing at it, and waits for the pod to be ready.
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

		// Poll until the profile is retrievable from storage before deploying.
		// Node-agent does a single fetch on container start with no retry.
		require.Eventually(t, func() bool {
			_, apErr := storageClient.ApplicationProfiles(ns.Name).Get(
				context.Background(), profileName, v1.GetOptions{})
			return apErr == nil
		}, 30*time.Second, 1*time.Second, "AP must be retrievable from storage before deploying the pod")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-profile-deployment.yaml"))
		require.NoError(t, err, "create workload in ns %s", ns.Name)
		require.NoError(t, wl.WaitForReady(80), "workload not ready in ns %s", ns.Name)

		// Wait for node-agent to load the user-defined profile into cache.
		time.Sleep(10 * time.Second)
		return wl
	}

	// triggerAndGetAlerts execs cat on the given path, then polls for alerts
	// up to 60s to avoid race conditions with alert propagation.
	triggerAndGetAlerts := func(t *testing.T, wl *testutils.TestWorkload, filePath string) []testutils.Alert {
		t.Helper()
		stdout, stderr, err := wl.ExecIntoPod([]string{"cat", filePath}, "nginx")
		if err != nil {
			t.Errorf("exec 'cat %s' in container nginx failed: %v (stdout=%q stderr=%q)", filePath, err, stdout, stderr)
		}
		// Poll for alerts — they may take time to propagate through
		// eBPF → node-agent → alertmanager.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			alerts, err = testutils.GetAlerts(wl.Namespace)
			return err == nil
		}, 60*time.Second, 5*time.Second, "alerts must be retrievable from ns %s", wl.Namespace)
		// Give extra time for all alerts to arrive after first successful fetch.
		time.Sleep(10 * time.Second)
		alerts, err = testutils.GetAlerts(wl.Namespace)
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

	// ---------------------------------------------------------------
	// 1c. Deploy known-application-profile-wildcards.yaml (curl image)
	//     and verify that files under wildcard-covered opens paths
	//     produce no R0002 alert.
	// ---------------------------------------------------------------
	t.Run("wildcard_yaml_profile_allowed_opens", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		wildcardProfileName := "fusioncore-profile-wildcards"

		// Create the profile matching known-application-profile-wildcards.yaml.
		profile := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wildcardProfileName,
				Namespace: ns.Name,
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
							{Path: "/etc/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/etc/ssl/openssl.cnf", Flags: []string{"O_RDONLY", "O_LARGEFILE"}},
							{Path: "/home/*", Flags: []string{"O_RDONLY", "O_LARGEFILE"}},
							{Path: "/lib/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/usr/lib/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/usr/local/lib/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
							{Path: "/proc/*/cgroup", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
							{Path: "/proc/*/kernel/cap_last_cap", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
							{Path: "/proc/*/mountinfo", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
							{Path: "/proc/*/task/*/fd", Flags: []string{"O_RDONLY", "O_DIRECTORY", "O_CLOEXEC"}},
							{Path: "/sys/fs/cgroup/cpu.max", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
							{Path: "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", Flags: []string{"O_RDONLY"}},
							{Path: "/7/setgroups", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
							{Path: "/runc", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
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
		_, err := storageClient.ApplicationProfiles(ns.Name).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create wildcard profile %q in ns %s", wildcardProfileName, ns.Name)

		// Poll until the profile is retrievable from storage before deploying.
		require.Eventually(t, func() bool {
			_, apErr := storageClient.ApplicationProfiles(ns.Name).Get(
				context.Background(), wildcardProfileName, v1.GetOptions{})
			return apErr == nil
		}, 30*time.Second, 1*time.Second, "AP must be retrievable before deploying the pod")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/curl-user-profile-wildcards-deployment.yaml"))
		require.NoError(t, err, "create curl workload in ns %s", ns.Name)
		require.NoError(t, wl.WaitForReady(80), "curl workload not ready in ns %s", ns.Name)

		// Wait for node-agent to load the user-defined profile into cache.
		time.Sleep(10 * time.Second)

		// Cat files that are covered by the wildcard opens.
		allowedFiles := []string{
			"/etc/hosts",           // covered by /etc/*
			"/etc/resolv.conf",     // covered by /etc/*
			"/etc/ssl/openssl.cnf", // exact match
		}
		for _, f := range allowedFiles {
			stdout, stderr, err := wl.ExecIntoPod([]string{"cat", f}, "curl")
			if err != nil {
				t.Logf("exec 'cat %s' failed: %v (stdout=%q stderr=%q)", f, err, stdout, stderr)
			}
		}

		// Poll for alerts to propagate.
		time.Sleep(15 * time.Second)
		alerts, err := testutils.GetAlerts(wl.Namespace)
		require.NoError(t, err, "get alerts from ns %s", wl.Namespace)

		var r0002Fired bool
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName &&
				a.Labels["comm"] == "cat" &&
				a.Labels["container_name"] == "curl" {
				r0002Fired = true
				break
			}
		}
		if r0002Fired {
			t.Errorf("expected NO R0002 for files covered by wildcard opens, but alert fired")
		}
		addResult("wildcard_yaml_profile_allowed_opens",
			"/etc/*, /etc/ssl/openssl.cnf", "/etc/hosts, /etc/resolv.conf, /etc/ssl/openssl.cnf",
			false, !r0002Fired,
			fmt.Sprintf("got R0002=%v, expected none for wildcard-covered files", r0002Fired))
	})
}

func Test_33_AnalyzeOpensWildcardAnchoring(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const ruleName = "Files Access Anomalies in container"
	const profileName = "nginx-regex-profile"

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
		t.Log("\n========== Test_33 Summary ==========")
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
			t.Logf("  [%s] %-50s profile=%-25s file=%-30s %s", status, r.name, r.profilePath, r.filePath, expect)
			if !r.passed {
				t.Logf("         -> %s", r.detail)
			}
		}
		if !anyFailed {
			t.Log("  All subtests passed.")
		}
		t.Log("======================================")
	}()

	// deployWithProfile creates a user-defined AP with a single Opens
	// entry (plus a couple of always-needed paths nginx hits at startup),
	// then deploys nginx with the user-defined-profile label pointing at
	// it and waits for the pod + cache load.
	deployWithProfile := func(t *testing.T, profilePath string) *testutils.TestWorkload {
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
						Opens: []v1beta1.OpenCalls{
							{Path: profilePath, Flags: []string{"O_RDONLY"}},
							// Dynamic linker fires this on every exec — keep
							// it whitelisted so it doesn't drown out the
							// signal we actually care about.
							{Path: "/etc/ld.so.cache", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
						},
					},
				},
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.ApplicationProfiles(ns.Name).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined profile %q in ns %s", profileName, ns.Name)

		require.Eventually(t, func() bool {
			_, apErr := storageClient.ApplicationProfiles(ns.Name).Get(
				context.Background(), profileName, v1.GetOptions{})
			return apErr == nil
		}, 30*time.Second, 1*time.Second, "AP must be retrievable from storage before deploying the pod")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-profile-deployment.yaml"))
		require.NoError(t, err, "create workload in ns %s", ns.Name)
		// 11 subtests deploy a fresh pod sequentially, so each later subtest
		// races against an increasingly loaded kind cluster — the upstream
		// CP cache reconciler, alertmanager, and prometheus all chew CPU at
		// boot. 80s timed out intermittently; 180s gives headroom without
		// pushing the total test runtime into a different regime.
		require.NoError(t, wl.WaitForReady(180), "workload not ready in ns %s", ns.Name)

		// Wait for node-agent to load the user-defined profile into cache.
		time.Sleep(10 * time.Second)
		return wl
	}

	// catAndAlerts execs `cat <path>` (ignoring cat's own exit error —
	// catting a directory or a non-readable file still triggers the
	// open() syscall the eBPF tracer captures), then polls for alerts.
	catAndAlerts := func(t *testing.T, wl *testutils.TestWorkload, filePath string) []testutils.Alert {
		t.Helper()
		stdout, stderr, _ := wl.ExecIntoPod([]string{"cat", filePath}, "nginx")
		t.Logf("cat %q → stdout=%q stderr=%q", filePath, stdout, stderr)

		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			a, err := testutils.GetAlerts(wl.Namespace)
			if err != nil {
				return false
			}
			alerts = a
			return true
		}, 60*time.Second, 5*time.Second, "alerts must be retrievable from ns %s", wl.Namespace)
		// Settle so any late R0002 alert lands before we count.
		time.Sleep(10 * time.Second)
		alerts, err := testutils.GetAlerts(wl.Namespace)
		require.NoError(t, err, "get alerts from ns %s", wl.Namespace)
		return alerts
	}

	// hasR0002 returns true if any R0002 alert fired for `cat` in the
	// nginx container.
	hasR0002 := func(alerts []testutils.Alert) bool {
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName &&
				a.Labels["comm"] == "cat" &&
				a.Labels["container_name"] == "nginx" {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name        string
		profilePath string
		filePath    string
		expectAlert bool
		why         string // contract pinned by this case
	}{
		// ─── Trailing-`*` anchoring (the security fix) ──────────────
		//
		// IMPORTANT: R0002's CEL ruleExpression has a strict prefix
		// filter (event.path.startsWith('/etc/'), startsWith('/var/log/'),
		// etc. — all with trailing slash). Bare `/etc` and `/var/log`
		// don't match those prefixes, so the rule never evaluates on
		// them and the matcher's anchoring contract stays invisible at
		// runtime. Probe one level deeper instead — `/etc/ssl` IS under
		// the `/etc/` monitored prefix, so R0002 CAN see whether a
		// `/etc/ssl/*` profile entry matches the bare `/etc/ssl` parent.
		{
			name:        "trailing_star_matches_immediate_child",
			profilePath: "/etc/*",
			filePath:    "/etc/hosts",
			expectAlert: false,
			why:         "/etc/* matches a one-segment child under /etc",
		},
		{
			name:        "trailing_star_matches_deep_child",
			profilePath: "/etc/*",
			filePath:    "/etc/ssl/openssl.cnf",
			expectAlert: false,
			why:         "/etc/* matches a multi-segment path under /etc (mid-path zero-or-more)",
		},
		{
			name:        "trailing_star_does_not_match_bare_parent_under_monitored_prefix",
			profilePath: "/etc/ssl/*",
			filePath:    "/etc/ssl",
			expectAlert: true,
			why:         "/etc/ssl/* must NOT match the bare /etc/ssl directory itself — pins the security fix at a path R0002's prefix filter can observe",
		},
		{
			name:        "deep_prefix_trailing_star_does_not_match_parent",
			profilePath: "/etc/ssl/certs/*",
			filePath:    "/etc/ssl/certs",
			expectAlert: true,
			why:         "Same anchoring rule, deeper: /etc/ssl/certs/* does NOT match /etc/ssl/certs",
		},

		// ─── DynamicIdentifier (⋯) exactly-one ──────────────────────
		{
			name:        "ellipsis_requires_one_segment_not_zero",
			profilePath: "/etc/passwd/" + dynamicpathdetector.DynamicIdentifier,
			filePath:    "/etc/passwd",
			expectAlert: true,
			why:         "⋯ consumes EXACTLY ONE segment; /etc/passwd/⋯ requires one more, /etc/passwd alone has zero past — must fire R0002",
		},

		// ─── Mixed ⋯/* combinations ─────────────────────────────────
		{
			name:        "ellipsis_then_trailing_star_matches_two_segment_tail",
			profilePath: "/proc/" + dynamicpathdetector.DynamicIdentifier + "/*",
			filePath:    "/proc/1/status",
			expectAlert: false,
			why:         "/proc/⋯/* matches /proc/1/status (⋯ consumes 1, * consumes ≥1)",
		},
		{
			name:        "ellipsis_then_trailing_star_matches_three_segment_tail",
			profilePath: "/proc/" + dynamicpathdetector.DynamicIdentifier + "/*",
			filePath:    "/proc/1/task/1",
			expectAlert: false,
			why:         "/proc/⋯/* matches deeper paths (⋯ consumes 1, * consumes ≥1 covering rest)",
		},

		// ─── Multiple trailing wildcards ────────────────────────────
		{
			name:        "double_trailing_matches_one_child",
			profilePath: "/etc/*/*",
			filePath:    "/etc/ssl",
			expectAlert: false,
			why:         "/etc/*/* matches /etc/ssh (mid-* consumes zero, trailing-* consumes one)",
		},
		{
			name:        "double_trailing_matches_deep_child",
			profilePath: "/etc/*/*",
			filePath:    "/etc/ssl/openssl.cnf",
			expectAlert: false,
			why:         "/etc/*/* matches /etc/ssl/openssl.cnf (mid-* consumes one, trailing-* consumes one)",
		},
		{
			name:        "double_trailing_does_not_match_parent_under_monitored_prefix",
			profilePath: "/etc/ssl/*/*",
			filePath:    "/etc/ssl",
			expectAlert: true,
			why:         "/etc/ssl/*/* requires at least one segment past /etc/ssl; bare /etc/ssl must NOT match (probed under /etc/ so R0002 sees it)",
		},

		// ─── splitPath trailing-slash normalisation ─────────────────
		{
			name:        "trailing_slash_in_profile_normalises_to_literal",
			profilePath: "/etc/passwd/",
			filePath:    "/etc/passwd",
			expectAlert: false,
			why:         "Profile `/etc/passwd/` is normalised to `/etc/passwd`; matches the literal at runtime",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("contract: %s", tc.why)
			wl := deployWithProfile(t, tc.profilePath)
			alerts := catAndAlerts(t, wl, tc.filePath)
			got := hasR0002(alerts)

			detail := fmt.Sprintf("got %d alerts total; R0002 fired = %v", len(alerts), got)
			passed := got == tc.expectAlert
			if !passed {
				if tc.expectAlert {
					t.Errorf("expected R0002 alert: profile %q must NOT match %q (%s); but no alert fired",
						tc.profilePath, tc.filePath, tc.why)
				} else {
					t.Errorf("expected NO R0002 alert: profile %q should match %q (%s); but alert fired",
						tc.profilePath, tc.filePath, tc.why)
				}
			}
			addResult(tc.name, tc.profilePath, tc.filePath, tc.expectAlert, passed, detail)
		})
	}
}

func Test_32_UnexpectedProcessArguments(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const overlayName = "curl-32-overlay"

	setup := func(t *testing.T) (*testutils.TestWorkload, int) {
		t.Helper()
		ns := testutils.NewRandomNamespace()
		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

		ap := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      overlayName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "curl",
						Execs: []v1beta1.ExecCalls{
							// Profile shape: Path AND Args[0] both use the
							// absolute-path symlink form (/bin/sh,
							// /usr/bin/nslookup, ...). With the symlink-
							// faithful precedence in parse.get_exec_path
							// (fix 9a6eb359), the rule queries the
							// symlink-as-invoked path that the kernel
							// preserves in argv[0]. Recording-side
							// resolveExecPath uses the same precedence so
							// auto-learned profiles get the same key.
							//
							// Storage's CompareExecArgs is a strict
							// positional compare — no special argv[0]
							// normalisation — so Args[0] MUST be the same
							// string as runtime argv[0]. For
							// kubectl-exec'd processes that's the absolute
							// path the caller invoked.
							//
							// pod startup: sleep <anything>
							{Path: "/bin/sleep", Args: []string{"/bin/sleep", dynamicpathdetector.ExecArgsWildcard}},
							// sh -c <anything trailing>
							{Path: "/bin/sh", Args: []string{"/bin/sh", "-c", dynamicpathdetector.ExecArgsWildcard}},
							// echo hello <anything trailing>
							{Path: "/bin/echo", Args: []string{"/bin/echo", "hello", dynamicpathdetector.ExecArgsWildcard}},
							// curl -s <one URL>
							{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "-s", dynamicpathdetector.DynamicIdentifier}},
							// curl -s <one URL> file:///etc/hosts file:///etc/hostname
							// — a ⋯ in a NON-trailing position: it matches exactly
							// one arg, and the LITERAL args after it must still
							// anchor. (file:// URLs are used as the post-⋯ literals
							// so curl reads local files and exits 0.)
							{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "-s", dynamicpathdetector.DynamicIdentifier, "file:///etc/hosts", "file:///etc/hostname"}},
							// Busybox-symlink mirror entries. The curl image's
							// /bin/{sleep,sh,echo} are symlinks to /bin/busybox,
							// so the kernel's resolved /proc/<pid>/exe — what
							// IG captures as event.exepath — is /bin/busybox.
							// parse.get_exec_path(args, comm, exepath) returns
							// exepath first, so ap.was_executed queries arrive
							// at the rule keyed on /bin/busybox, not the
							// symlink form. Without a matching profile entry
							// keyed on /bin/busybox, R0001 fires before R0040
							// ever evaluates and the test trips its R0001
							// precondition. The symlink-form entries above are
							// retained for environments where exepath resolves
							// to the as-invoked path (non-symlinked utilities;
							// fexecve / argv[0] fallback in resolveExecPath).
							{Path: "/bin/busybox", Args: []string{"/bin/sleep", dynamicpathdetector.ExecArgsWildcard}},
							{Path: "/bin/busybox", Args: []string{"/bin/sh", "-c", dynamicpathdetector.ExecArgsWildcard}},
							{Path: "/bin/busybox", Args: []string{"/bin/echo", "hello", dynamicpathdetector.ExecArgsWildcard}},
							// Literal "*" arg: echo invoked with a GENUINE literal "*"
							// (e.g. an unexpanded glob), recorded verbatim. Under the
							// symbol contract a "*" in argv is DATA, not a wildcard, so
							// this entry matches ONLY `echo star *` and must NOT broaden
							// to `echo star <other>`. CT-level mirror of storage's
							// TestAP_LiteralStarVsDynamic. (busybox + symlink forms.)
							{Path: "/bin/echo", Args: []string{"/bin/echo", "star", "*"}},
							{Path: "/bin/busybox", Args: []string{"/bin/echo", "star", "*"}},
						},
						Syscalls: []string{"socket", "connect", "sendto", "recvfrom", "read", "write", "close", "openat", "mmap", "mprotect", "munmap", "fcntl", "ioctl", "poll", "epoll_create1", "epoll_ctl", "epoll_wait", "bind", "listen", "accept4", "getsockopt", "setsockopt", "getsockname", "getpid", "fstat", "rt_sigaction", "rt_sigprocmask", "writev", "execve"},
					},
				},
			},
		}
		_, err := storageClient.ApplicationProfiles(ns.Name).Create(
			context.Background(), ap, metav1.CreateOptions{})
		require.NoError(t, err, "create AP")

		// User-supplied SBOB pattern (mirrors Test_28): the pod carries BOTH
		// kubescape.io/user-defined-profile and kubescape.io/user-defined-network.
		// Node-agent uses the single overlay name as the lookup key for BOTH
		// the user ApplicationProfile and the user NetworkNeighborhood, so the
		// NN must exist under the same name and be created before the pod.
		// User-authored objects carry managed-by=User + a terminal
		// status/completion and the workload-binding labels.
		nn := &v1beta1.NetworkNeighborhood{
			ObjectMeta: metav1.ObjectMeta{
				Name:      overlayName,
				Namespace: ns.Name,
				Annotations: map[string]string{
					helpersv1.ManagedByMetadataKey:  helpersv1.ManagedByUserValue,
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
					helpersv1.CompletionMetadataKey: helpersv1.Full,
				},
				Labels: map[string]string{
					helpersv1.ApiGroupMetadataKey:         "apps",
					helpersv1.ApiVersionMetadataKey:       "v1",
					helpersv1.RelatedKindMetadataKey:      "Deployment",
					helpersv1.RelatedNameMetadataKey:      "curl-32",
					helpersv1.RelatedNamespaceMetadataKey: ns.Name,
				},
			},
			Spec: v1beta1.NetworkNeighborhoodSpec{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "curl-32"},
				},
				Containers: []v1beta1.NetworkNeighborhoodContainer{
					{Name: "curl"},
				},
			},
		}
		_, err = storageClient.NetworkNeighborhoods(ns.Name).Create(
			context.Background(), nn, metav1.CreateOptions{})
		require.NoError(t, err, "create NN")

		require.Eventually(t, func() bool {
			_, apErr := storageClient.ApplicationProfiles(ns.Name).Get(
				context.Background(), overlayName, v1.GetOptions{})
			_, nnErr := storageClient.NetworkNeighborhoods(ns.Name).Get(
				context.Background(), overlayName, v1.GetOptions{})
			return apErr == nil && nnErr == nil
		}, 30*time.Second, 1*time.Second, "AP+NN must be in storage before pod deploy")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/curl-exec-arg-wildcards-deployment.yaml"))
		require.NoError(t, err)
		require.NoError(t, wl.WaitForReady(80))

		// Deterministic profile-load gate (replaces a fixed sleep that raced the
		// asynchronous overlay load). node-agent must observe the pod, resolve
		// the kubescape.io/user-defined-profile annotation to UserAPRef, fetch
		// the user AP and build the projection before the argv-comparison rule
		// (R0040) can evaluate at all; until then refreshOneEntry reports the CP
		// "not-available" and R0040 is suppressed — which makes every POSITIVE
		// subtest pass VACUOUSLY (no profile -> no R0040 -> ==0) and every
		// NEGATIVE subtest time out. The fixed 30s sleep did not reliably cover
		// that window (observed: all negatives failing on a slow load).
		//
		// The canary is a deterministic argv MISMATCH: [echo, <probe>] matches
		// neither [echo, hello, ⋯⋯] nor [echo, star, *], so once the overlay is
		// projected it MUST fire R0040. R0040's cooldown key is uniqueId =
		// comm+exepath+argv, so this distinct argv never suppresses a subtest's
		// own R0040. We retry until it fires, then return the post-gate R0040
		// count as a baseline so subtests assert on the DELTA, not absolutes —
		// closing the vacuous-positive hole.
		countR0040 := func(alerts []testutils.Alert) int {
			n := 0
			for _, a := range alerts {
				if a.Labels["rule_id"] == "R0040" {
					n++
				}
			}
			return n
		}
		require.Eventually(t, func() bool {
			if _, _, err := wl.ExecIntoPod([]string{"echo", "__profile_probe__"}, "curl"); err != nil {
				return false
			}
			alerts, _ := testutils.GetAlerts(ns.Name)
			return countR0040(alerts) > 0
		}, 180*time.Second, 10*time.Second,
			"user overlay must project (canary R0040 must fire) before subtests run")
		// settle so all in-flight canary alerts are counted into the baseline
		time.Sleep(10 * time.Second)
		alerts, _ := testutils.GetAlerts(ns.Name)
		return wl, countR0040(alerts)
	}

	countByRule := func(alerts []testutils.Alert, ruleID string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID {
				n++
			}
		}
		return n
	}

	waitAlerts := func(t *testing.T, ns string) []testutils.Alert {
		t.Helper()
		var alerts []testutils.Alert
		var err error
		require.Eventually(t, func() bool {
			alerts, err = testutils.GetAlerts(ns)
			return err == nil
		}, 60*time.Second, 5*time.Second, "must be able to fetch alerts")
		// settle time for any in-flight alerts
		time.Sleep(10 * time.Second)
		alerts, _ = testutils.GetAlerts(ns)
		return alerts
	}

	logAlerts := func(t *testing.T, alerts []testutils.Alert) {
		t.Helper()
		for i, a := range alerts {
			t.Logf("  [%d] %s(%s) comm=%s container=%s",
				i, a.Labels["rule_name"], a.Labels["rule_id"],
				a.Labels["comm"], a.Labels["container_name"])
		}
	}

	// R0001 silence is a precondition for every subtest below: it means
	// parse.get_exec_path resolved to the profile's Path key, so R0040
	// gets to evaluate its argv comparison cleanly. A non-zero R0001 for
	// the test binary's comm means the recording / capture / resolution
	// chain dropped event.exepath — that's a separate bug (track it in
	// the recording side, not in R0040), and asserting it here fails the
	// subtest on the right axis instead of polluting the R0040 signal.
	assertR0001Silent := func(t *testing.T, alerts []testutils.Alert, comm string) {
		t.Helper()
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R0001" && a.Labels["comm"] == comm {
				n++
			}
		}
		require.Zero(t, n,
			"R0001 precondition: path resolution failed for comm=%q. "+
				"parse.get_exec_path either didn't receive event.exepath or "+
				"profile Path doesn't match its return value. Fix capture-side "+
				"exepath before reading R0040 results from this subtest.", comm)
	}

	// -----------------------------------------------------------------
	// 32a. sh -c <anything>  — argv [sh, -c, "echo hi"] matches
	//      profile [sh, -c, ⋯⋯]. R0040 must NOT fire.
	// -----------------------------------------------------------------
	t.Run("sh_dash_c_matches_wildcard_trailing", func(t *testing.T) {
		wl, base := setup(t)
		// Warm the cache: retry the exec until it runs cleanly so the user
		// overlay is loaded, then settle and assert R0040 stays silent
		// (mirrors Test_28 no-alert idiom). A matching argv must not alert.
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"sh", "-c", "echo hi"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "sh")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"sh -c <cmd> matches profile [sh, -c, ⋯⋯]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32b. sh -x -c <cmd>  — argv [sh, -x, -c, "echo hi"] does NOT match
	//      profile [sh, -c, ⋯⋯] (literal anchor `-c` at position 1 mismatches
	//      `-x`). Path /bin/sh (or /bin/busybox) IS in profile so R0001
	//      stays silent. R0040 must fire.
	//
	//      Earlier shape `sh -x "echo hi"` exited 2 (busybox sh tried to
	//      open "echo hi" as a script file) — kubectl exec returned an
	//      error and require.NoError tripped before R0040 could be read.
	//      Adding -c keeps sh's invocation valid while preserving the
	//      argv-shape mismatch that exercises R0040.
	// -----------------------------------------------------------------
	t.Run("sh_dash_x_mismatches_R0040", func(t *testing.T) {
		wl, base := setup(t)
		// Retry the trigger until node-agent has loaded the user overlay
		// into the ContainerProfileCache and R0040 fires. The overlay loads
		// asynchronously, so a single exec can race the load and the
		// profile-dependent rule is suppressed (mirrors Test_28). The
		// command is idempotent, so re-exec is side-effect-free.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"sh", "-x", "-c", "echo hi"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "sh -x mismatches profile [sh, -c, ⋯⋯]: R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "sh")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"sh -x mismatches profile [sh, -c, ⋯⋯]: R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32c. echo hello <anything> — argv [echo, hello, world, from, test]
	//      matches profile [echo, hello, ⋯⋯]. R0040 must NOT fire.
	// -----------------------------------------------------------------
	t.Run("echo_hello_matches_wildcard_trailing", func(t *testing.T) {
		wl, base := setup(t)
		// Warm the cache: retry the exec until it runs cleanly so the user
		// overlay is loaded, then settle and assert R0040 stays silent
		// (mirrors Test_28 no-alert idiom). A matching argv must not alert.
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "hello", "world", "from", "test"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"echo hello <words> matches profile [echo, hello, ⋯⋯]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32d. echo goodbye <anything> — argv [echo, goodbye, world] does
	//      NOT match profile [echo, hello, ⋯⋯] (literal anchor `hello`
	//      mismatch). R0040 must fire.
	// -----------------------------------------------------------------
	t.Run("echo_goodbye_mismatches_R0040", func(t *testing.T) {
		wl, base := setup(t)
		// Retry the trigger until node-agent has loaded the user overlay
		// into the ContainerProfileCache and R0040 fires. The overlay loads
		// asynchronously, so a single exec can race the load and the
		// profile-dependent rule is suppressed (mirrors Test_28). The
		// command is idempotent, so re-exec is side-effect-free.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "goodbye", "world"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "echo goodbye <words> mismatches profile [echo, hello, ⋯⋯] (literal anchor): R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"echo goodbye <words> mismatches profile [echo, hello, ⋯⋯] (literal anchor): R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32e. curl -s <one URL> — the NON-symlinked binary (curl is a real
	//      binary in curlimages/curl, not a busybox applet) with an
	//      ELLIPSIS profile: [curl, -s, ⋯]. ⋯ matches EXACTLY ONE arg, so
	//      `curl -s <single url>` matches → R0040 silent.
	//
	//      A file:// URL is used so curl reads a local file and exits 0
	//      regardless of cluster egress — the test pins argv matching, not
	//      network reachability.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_one_url_matches_ellipsis", func(t *testing.T) {
		wl, base := setup(t)
		// Warm the cache: retry the exec until it runs cleanly so the user
		// overlay is loaded, then settle and assert R0040 stays silent
		// (mirrors Test_28 no-alert idiom). A matching argv must not alert.
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/hostname"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"curl -s <one url> matches profile [curl, -s, dyn]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32f. curl -s <two URLs> — argv [curl, -s, url1, url2] does NOT match
	//      profile [curl, -s, ⋯] because ⋯ consumes EXACTLY ONE arg, not
	//      two. R0040 must fire. Pins the ⋯ (DynamicIdentifier) arity on
	//      the non-symlinked path. Both file:// URLs are readable so curl
	//      still exits 0.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_two_urls_mismatches_R0040", func(t *testing.T) {
		wl, base := setup(t)
		// Retry the trigger until node-agent has loaded the user overlay
		// into the ContainerProfileCache and R0040 fires. The overlay loads
		// asynchronously, so a single exec can race the load and the
		// profile-dependent rule is suppressed (mirrors Test_28). The
		// command is idempotent, so re-exec is side-effect-free.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/hostname", "file:///etc/hosts"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "curl -s <two urls> exceeds the single-arg dyn token in profile [curl, -s, dyn]: R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"curl -s <two urls> exceeds the single-arg dyn token in profile [curl, -s, dyn]: R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32g. echo star <other> — argv [echo, star, boom] does NOT match
	//      profile [echo, star, *] because the profile's "*" is a LITERAL
	//      character, not a wildcard. The path IS in profile (R0001 silent)
	//      but the argv mismatches at position 2 → R0040 must fire. This is
	//      the core symbol-contract guard: a recorded literal "*" must NOT
	//      broaden to an arbitrary arg (the over-broadening that blocked the
	//      merge). Mirrors storage's TestAP_LiteralStarVsDynamic.
	// -----------------------------------------------------------------
	t.Run("echo_literal_star_does_not_broaden_R0040", func(t *testing.T) {
		wl, base := setup(t)
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "star", "boom"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "echo star boom mismatches profile [echo, star, *] (literal star, no broaden): R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"echo star boom mismatches profile [echo, star, *] (literal star, no broaden): R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32h. echo star "*" — argv [echo, star, *] (a genuine literal "*"
	//      argument, passed unexpanded via exec, no shell) DOES match
	//      profile [echo, star, *] exactly. R0040 must stay silent. Pins the
	//      other half of the literal-"*" contract: data matches its own
	//      value verbatim.
	// -----------------------------------------------------------------
	t.Run("echo_literal_star_matches_itself", func(t *testing.T) {
		wl, base := setup(t)
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "star", "*"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"echo star * matches profile [echo, star, *] (literal): R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32i. curl -s <one URL> file:///etc/hosts file:///etc/hostname —
	//      argv [curl, -s, <url>, file:///etc/hosts, file:///etc/hostname]
	//      matches profile [curl, -s, ⋯, file:///etc/hosts,
	//      file:///etc/hostname]. The ⋯ sits MID-VECTOR: it consumes exactly
	//      the one <url> arg, and the two LITERAL args after it anchor. All
	//      three URLs are readable file:// paths so curl exits 0. R0040 must
	//      stay silent.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_mid_ellipsis_then_literals_matches", func(t *testing.T) {
		wl, base := setup(t)
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/group", "file:///etc/hosts", "file:///etc/hostname"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"curl -s <url> file:///etc/hosts file:///etc/hostname matches profile [curl, -s, ⋯, <lit>, <lit>]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32j. curl -s <one URL> file:///etc/hosts file:///etc/group — the LAST
	//      literal mismatches the profile's anchor (profile ends
	//      file:///etc/hostname, runtime ends file:///etc/group). The ⋯ and
	//      the first literal still match, so this pins that literals AFTER a
	//      mid-vector ⋯ are enforced — a mismatch there fires R0040. All URLs
	//      are readable so curl exits 0; only the argv shape differs.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_mid_ellipsis_trailing_literal_mismatch_R0040", func(t *testing.T) {
		wl, base := setup(t)
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/group", "file:///etc/hosts", "file:///etc/group"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "curl trailing literal mismatches profile [curl, -s, ⋯, <lit>, file:///etc/hostname]: R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"curl trailing literal mismatches profile [curl, -s, ⋯, <lit>, file:///etc/hostname]: R0040 must fire")
	})
}

func Test_28_UserDefinedNetworkNeighborhood(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// setup creates a namespace with user-defined AP + NN + pod.
	// The NN allows only fusioncore.ai (162.0.217.171) on TCP/80.
	setup := func(t *testing.T) *testutils.TestWorkload {
		t.Helper()
		ns := testutils.NewRandomNamespace()
		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

		// Upstream ContainerProfileCache (kubescape/node-agent#788) reads ONE
		// pod label `kubescape.io/user-defined-profile=<name>` and uses
		// <name> as the lookup key for BOTH the user AP and the user NN.
		// AP and NN MUST therefore share that single name.
		const overlayName = "curl-28-overlay"

		ap := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      overlayName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "curl",
						Execs: []v1beta1.ExecCalls{
							{Path: "/bin/sleep"},
							{Path: "/usr/bin/curl"},
							{Path: "/usr/bin/nslookup"},
							{Path: "/usr/bin/wget"},
						},
						Syscalls: []string{"socket", "connect", "sendto", "recvfrom", "read", "write", "close", "openat", "mmap", "mprotect", "munmap", "fcntl", "ioctl", "poll", "epoll_create1", "epoll_ctl", "epoll_wait", "bind", "listen", "accept4", "getsockopt", "setsockopt", "getsockname", "getpid", "fstat", "rt_sigaction", "rt_sigprocmask", "writev"},
					},
				},
			},
		}
		_, err := storageClient.ApplicationProfiles(ns.Name).Create(
			context.Background(), ap, metav1.CreateOptions{})
		require.NoError(t, err, "create AP")

		nn := &v1beta1.NetworkNeighborhood{
			ObjectMeta: metav1.ObjectMeta{
				Name:      overlayName,
				Namespace: ns.Name,
				Annotations: map[string]string{
					helpersv1.ManagedByMetadataKey:  helpersv1.ManagedByUserValue,
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
					helpersv1.CompletionMetadataKey: helpersv1.Full,
				},
				Labels: map[string]string{
					helpersv1.ApiGroupMetadataKey:   "apps",
					helpersv1.ApiVersionMetadataKey: "v1",
					helpersv1.RelatedKindMetadataKey:       "Deployment",
					helpersv1.RelatedNameMetadataKey:       "curl-28",
					helpersv1.RelatedNamespaceMetadataKey:  ns.Name,
				},
			},
			Spec: v1beta1.NetworkNeighborhoodSpec{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "curl-28"},
				},
				Containers: []v1beta1.NetworkNeighborhoodContainer{
					{
						Name: "curl",
						Egress: []v1beta1.NetworkNeighbor{
							{
								Identifier: "fusioncore-egress",
								Type:       "external",
								DNS:        "fusioncore.ai.",
								DNSNames:   []string{"fusioncore.ai."},
								IPAddress:  "162.0.217.171",
								Ports: []v1beta1.NetworkPort{
									{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))},
								},
							},
						},
					},
				},
			},
		}
		_, err = storageClient.NetworkNeighborhoods(ns.Name).Create(
			context.Background(), nn, metav1.CreateOptions{})
		require.NoError(t, err, "create NN")

		require.Eventually(t, func() bool {
			_, apErr := storageClient.ApplicationProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
			_, nnErr := storageClient.NetworkNeighborhoods(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
			return apErr == nil && nnErr == nil
		}, 30*time.Second, 1*time.Second, "AP+NN must be in storage before pod deploy")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-defined-deployment.yaml"))
		require.NoError(t, err)
		require.NoError(t, wl.WaitForReady(80))
		// Cache-load latency on the upstream ContainerProfileCache is bursty
		// — 15s is enough on a quiet runner but not on a loaded one. The
		// failure mode is alert metadata `errorMessage:"waiting for profile
		// update"`, which means the rule manager evaluated against an
		// unloaded NN and fired R0005/R0011 spuriously. 30s covers the
		// observed worst-case in CI without pushing total test time too
		// far. Real fix would be to poll a cache-loaded signal, but no
		// such signal is exposed today.
		time.Sleep(30 * time.Second)
		return wl
	}

	countByRule := func(alerts []testutils.Alert, ruleID string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID {
				n++
			}
		}
		return n
	}

	waitAlerts := func(t *testing.T, ns string) []testutils.Alert {
		t.Helper()
		var alerts []testutils.Alert
		var err error
		require.Eventually(t, func() bool {
			alerts, err = testutils.GetAlerts(ns)
			return err == nil
		}, 60*time.Second, 5*time.Second, "must be able to fetch alerts")
		// Extra settle time for remaining alerts.
		time.Sleep(10 * time.Second)
		alerts, _ = testutils.GetAlerts(ns)
		return alerts
	}

	logAlerts := func(t *testing.T, alerts []testutils.Alert) {
		t.Helper()
		for i, a := range alerts {
			t.Logf("  [%d] %s(%s) comm=%s container=%s",
				i, a.Labels["rule_name"], a.Labels["rule_id"],
				a.Labels["comm"], a.Labels["container_name"])
		}
	}

	// ---------------------------------------------------------------
	// 28a. Allowed traffic — fusioncore.ai is in the NN.
	//      No R0005 (DNS) and no R0011 (egress) expected.
	// ---------------------------------------------------------------
	t.Run("allowed_fusioncore_no_alert", func(t *testing.T) {
		wl := setup(t)

		// DNS lookup via nslookup (domain in NN).
		stdout, stderr, err := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
		t.Logf("nslookup fusioncore.ai → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		// HTTP via curl (domain + IP in NN).
		stdout, stderr, err = wl.ExecIntoPod([]string{"curl", "-sm5", "http://fusioncore.ai"}, "curl")
		t.Logf("curl fusioncore.ai → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		assert.Equal(t, 0, countByRule(alerts, "R0005"),
			"fusioncore.ai is in NN — should NOT fire R0005")
		assert.Equal(t, 0, countByRule(alerts, "R0011"),
			"fusioncore.ai IP is in NN — should NOT fire R0011")
	})

	// ---------------------------------------------------------------
	// 28b. Unknown domains — domains NOT in the NN → R0005.
	//      Uses both nslookup (pure DNS) and curl (DNS + TCP).
	// ---------------------------------------------------------------
	t.Run("unknown_domain_R0005", func(t *testing.T) {
		wl := setup(t)

		// nslookup generates a DNS query without any TCP connection.
		wl.ExecIntoPod([]string{"nslookup", "google.com"}, "curl")
		// curl resolves + connects.
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://ebpf.io"}, "curl")
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://cloudflare.com"}, "curl")

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		require.Greater(t, countByRule(alerts, "R0005"), 0,
			"unknown domains must fire R0005")
	})

	// ---------------------------------------------------------------
	// 28c. Unknown IPs — raw IP egress NOT in the NN → R0011.
	// ---------------------------------------------------------------
	t.Run("unknown_ip_R0011", func(t *testing.T) {
		wl := setup(t)

		wl.ExecIntoPod([]string{"curl", "-sm5", "http://8.8.8.8"}, "curl")
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://1.1.1.1"}, "curl")

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		require.Greater(t, countByRule(alerts, "R0011"), 0,
			"IPs not in NN must fire R0011")
	})

	// ---------------------------------------------------------------
	// 28d. MITM — DNS spoofing simulation.
	//      fusioncore.ai is an allowed domain but the IP is spoofed.
	//
	//      Step 1: nslookup fusioncore.ai (legitimate DNS, no alert).
	//      Step 2: curl --resolve fusioncore.ai:80:8.8.4.4
	//              Simulates a DNS MITM returning a different IP.
	//              The domain is allowed but the connection goes to
	//              8.8.4.4 (not 162.0.217.171) → R0011.
	// ---------------------------------------------------------------
	t.Run("mitm_spoofed_ip_R0011", func(t *testing.T) {
		wl := setup(t)

		// Step 1: Legitimate DNS lookup — no alert expected.
		wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")

		// Step 2: MITM — domain resolves to spoofed IP 8.8.4.4.
		// curl --resolve skips DNS and connects directly to the
		// spoofed IP, simulating what happens after DNS poisoning.
		stdout, stderr, err := wl.ExecIntoPod(
			[]string{"curl", "-sm5", "--resolve", "fusioncore.ai:80:8.8.4.4", "http://fusioncore.ai"}, "curl")
		t.Logf("curl MITM → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		require.Greater(t, countByRule(alerts, "R0011"), 0,
			"MITM: fusioncore.ai allowed but spoofed IP 8.8.4.4 must fire R0011")
	})

	// ---------------------------------------------------------------
	// 28e. MITM — real CoreDNS poisoning via template plugin.
	//      Poisons CoreDNS so fusioncore.ai resolves to 8.8.4.4
	//      instead of the legitimate 162.0.217.171.
	//
	//      nslookup triggers the poisoned DNS response.
	//      R0005 does NOT fire: fusioncore.ai is in the NN egress
	//      list and BusyBox nslookup does NOT do PTR reverse-lookups.
	//      R0011 does NOT fire: no TCP egress (DNS is UDP to cluster
	//      DNS which is a private IP filtered by is_private_ip).
	//
	//      This documents a detection gap: pure DNS MITM (without
	//      subsequent TCP to the spoofed IP) is invisible to both
	//      R0005 and R0011 when the domain is already whitelisted.
	//
	//      NOTE: this subtest MUST run last — it modifies the
	//      cluster-wide CoreDNS configmap.
	// ---------------------------------------------------------------
	t.Run("mitm_coredns_poisoning", func(t *testing.T) {
		wl := setup(t)
		ctx := context.Background()
		k8sClient := k8sinterface.NewKubernetesApi()

		// ── Back up original CoreDNS Corefile ──
		cm, err := k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
		require.NoError(t, err, "get coredns configmap")
		originalCorefile := cm.Data["Corefile"]

		restartAndWaitCoreDNS := func() {
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			require.NoError(t, err, "get coredns deployment")
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			_, err = k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{})
			require.NoError(t, err, "restart coredns")

			require.Eventually(t, func() bool {
				d, err := k8sClient.KubernetesClient.AppsV1().
					Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if err != nil || d.Spec.Replicas == nil {
					return false
				}
				return d.Status.ReadyReplicas == *d.Spec.Replicas &&
					d.Status.UpdatedReplicas == *d.Spec.Replicas
			}, 60*time.Second, 2*time.Second, "coredns must become ready")
		}

		// ── Restore CoreDNS on cleanup (best-effort) ──
		t.Cleanup(func() {
			t.Log("cleanup: restoring CoreDNS Corefile")
			cm, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns cm: %v", err)
				return
			}
			cm.Data["Corefile"] = originalCorefile
			if _, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: update coredns cm: %v", err)
				return
			}
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns deploy: %v", err)
				return
			}
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			if _, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: restart coredns: %v", err)
			}
		})

		// ── Poison CoreDNS: fusioncore.ai → 8.8.4.4 ──
		poisoned := strings.Replace(originalCorefile,
			"forward .",
			"template IN A fusioncore.ai {\n        answer \"fusioncore.ai. 60 IN A 8.8.4.4\"\n        fallthrough\n    }\n    forward .",
			1)
		require.NotEqual(t, originalCorefile, poisoned, "template injection must modify Corefile")

		cm.Data["Corefile"] = poisoned
		_, err = k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{})
		require.NoError(t, err, "apply poisoned Corefile")
		restartAndWaitCoreDNS()

		// Verify poisoned DNS returns the spoofed IP.
		require.Eventually(t, func() bool {
			stdout, _, _ := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
			return strings.Contains(stdout, "8.8.4.4")
		}, 30*time.Second, 3*time.Second, "poisoned CoreDNS must return 8.8.4.4 for fusioncore.ai")

		// ── Trigger alerts ──
		// nslookup does DNS only (no TCP egress).
		// BusyBox nslookup does NOT do PTR reverse-lookups on result IPs.
		stdout, stderr, err := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
		t.Logf("nslookup (poisoned) → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		// R0005 does NOT fire: fusioncore.ai is already in the NN
		// egress list, and BusyBox nslookup does NOT perform PTR
		// reverse-lookups on result IPs, so no unknown domain is queried.
		assert.Equal(t, 0, countByRule(alerts, "R0005"),
			"DNS MITM: domain is in NN and no PTR lookup — R0005 should not fire")

		// R0011 does NOT fire: nslookup generates only DNS (UDP)
		// traffic to the cluster DNS service, which is a private IP
		// excluded by is_private_ip().
		assert.Equal(t, 0, countByRule(alerts, "R0011"),
			"DNS MITM: nslookup has no TCP egress — R0011 should not fire")
	})

	// ---------------------------------------------------------------
	// 28f. MITM — CoreDNS poisoning with TCP egress.
	//      Same CoreDNS poisoning as 28e, but now fusioncore.ai
	//      resolves to 128.130.194.56 (a routable IP that accepts
	//      TCP on port 80).  curl generates a real TCP connection
	//      to the spoofed IP.
	//
	//      Expected:
	//        R0005 = 0 — domain is in NN, no PTR reverse-lookup.
	//        R0011 fires — TCP egress to 128.130.194.56 which is
	//                       NOT in the NN (NN only has 162.0.217.171).
	//
	//      NOTE: runs after 28e; modifies cluster-wide CoreDNS.
	// ---------------------------------------------------------------
	t.Run("mitm_coredns_poisoning_tcp", func(t *testing.T) {
		wl := setup(t)
		ctx := context.Background()
		k8sClient := k8sinterface.NewKubernetesApi()

		// ── Back up original CoreDNS Corefile ──
		cm, err := k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
		require.NoError(t, err, "get coredns configmap")
		originalCorefile := cm.Data["Corefile"]

		restartAndWaitCoreDNS := func() {
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			require.NoError(t, err, "get coredns deployment")
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			_, err = k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{})
			require.NoError(t, err, "restart coredns")

			require.Eventually(t, func() bool {
				d, err := k8sClient.KubernetesClient.AppsV1().
					Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if err != nil || d.Spec.Replicas == nil {
					return false
				}
				return d.Status.ReadyReplicas == *d.Spec.Replicas &&
					d.Status.UpdatedReplicas == *d.Spec.Replicas
			}, 60*time.Second, 2*time.Second, "coredns must become ready")
		}

		// ── Restore CoreDNS on cleanup (best-effort) ──
		t.Cleanup(func() {
			t.Log("cleanup: restoring CoreDNS Corefile")
			cm, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns cm: %v", err)
				return
			}
			cm.Data["Corefile"] = originalCorefile
			if _, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: update coredns cm: %v", err)
				return
			}
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns deploy: %v", err)
				return
			}
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			if _, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: restart coredns: %v", err)
			}
		})

		// ── Poison CoreDNS: fusioncore.ai → 128.130.194.56 ──
		poisoned := strings.Replace(originalCorefile,
			"forward .",
			"template IN A fusioncore.ai {\n        answer \"fusioncore.ai. 60 IN A 128.130.194.56\"\n        fallthrough\n    }\n    forward .",
			1)
		require.NotEqual(t, originalCorefile, poisoned, "template injection must modify Corefile")

		cm.Data["Corefile"] = poisoned
		_, err = k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{})
		require.NoError(t, err, "apply poisoned Corefile")
		restartAndWaitCoreDNS()

		// Verify poisoned DNS returns the spoofed IP.
		require.Eventually(t, func() bool {
			stdout, _, _ := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
			return strings.Contains(stdout, "128.130.194.56")
		}, 30*time.Second, 3*time.Second, "poisoned CoreDNS must return 128.130.194.56 for fusioncore.ai")

		// ── Trigger alerts ──
		// curl resolves fusioncore.ai → 128.130.194.56 (poisoned)
		// then opens a TCP connection to 128.130.194.56:80.
		stdout, stderr, err := wl.ExecIntoPod(
			[]string{"curl", "-sm5", "http://fusioncore.ai"}, "curl")
		t.Logf("curl (poisoned DNS) → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		// R0005 does NOT fire: fusioncore.ai is already in the NN
		// egress list, and curl (like BusyBox nslookup) does NOT
		// perform PTR reverse-lookups on resolved IPs.
		assert.Equal(t, 0, countByRule(alerts, "R0005"),
			"DNS MITM: domain is in NN and no PTR lookup — R0005 should not fire")

		// R0011 fires: TCP egress to 128.130.194.56 which is NOT
		// in the NN (NN only allows 162.0.217.171).
		require.Greater(t, countByRule(alerts, "R0011"), 0,
			"DNS MITM: TCP to spoofed IP 128.130.194.56 must fire R0011")
	})
}

// Test_34_NetworkNeighborsCIDRCollapse is an end-to-end test for storage
// PR kubescape/storage#348 (CIDR-based collapsing of NetworkNeighbor entries).
//
// The collapse runs entirely on the storage side, in the PreSave/deflate path,
// using the compiled-in defaults (NetworkIPGroupThreshold=50, floor /16), so the
// test needs no workload pod and no config. It writes one NetworkNeighborhood
// modelling a "curl" client with two external destinations, each an egress group
// of 60 host IPs (> the 50 threshold) differing only by address:
//
//   - an S3-style endpoint whose addresses cluster in a single /24
//     (52.216.183.0/24, last octet spanning the top bit)  -> collapses to /24
//   - a broader CDN-style endpoint spanning a whole /16
//     (100.68.0.0/16, third octet spanning the top bit)   -> collapses to /16
//
// so both the single-covering-/24 and floor-/16 paths are exercised. Groups are
// keyed by DNS, so the two destinations collapse independently.
//
// Version note: the collapse output lands in the plural `ipAddresses` field,
// which exists only on PR#348 storage — not on the pinned upstream storage Go
// types this test compiles against. We therefore read the result back through
// the DYNAMIC client, so the new field is never referenced at compile time and
// is not silently dropped at decode time. The test compiles on plain upstream
// but only passes when storage carries PR#348 — exactly the e2e contract we want.
func Test_34_NetworkNeighborsCIDRCollapse(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
	dyn := dynamic.NewForConfigOrDie(k8sClient.K8SConfig)
	ctx := context.Background()

	nnGVR := schema.GroupVersionResource{
		Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "networkneighborhoods",
	}
	ccGVR := schema.GroupVersionResource{
		Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "collapseconfigurations",
	}

	// ONE cluster-scoped CollapseConfiguration singleton drives BOTH the network
	// CIDR collapse (PR#348: networkIPGroupThreshold / networkCIDRFloorBits) AND
	// the pre-existing path/endpoint collapse (openDynamicThreshold /
	// endpointDynamicThreshold). We set every knob low so each scenario trips
	// deterministically — and, crucially, so the mixed subtest can prove the two
	// collapse families do NOT interfere. Untyped: the network fields exist only
	// on PR#348 storage. Note the network floor is set to /16 explicitly — the
	// shipped default is /24 (NetworkCIDRFloorBits=24), NOT the documented 16.
	cc := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
		"kind":       "CollapseConfiguration",
		"metadata":   map[string]interface{}{"name": "default"},
		"spec": map[string]interface{}{
			"networkIPGroupThreshold":  int64(5),
			"networkCIDRFloorBits":     int64(16),
			"openDynamicThreshold":     int64(5),
			"endpointDynamicThreshold": int64(5),
		},
	}}
	if _, ccErr := dyn.Resource(ccGVR).Create(ctx, cc, metav1.CreateOptions{}); ccErr != nil && !apierrors.IsAlreadyExists(ccErr) {
		require.NoError(t, ccErr, "apply CollapseConfiguration")
	}
	t.Cleanup(func() { _ = dyn.Resource(ccGVR).Delete(ctx, "default", metav1.DeleteOptions{}) })

	const hostCount = 60 // comfortably above every threshold (5 here, 50 default)

	// hostGroup builds `count` external egress entries that differ only by IP and
	// share one DNS name, so storage groups them together for collapsing.
	hostGroup := func(dns string, count int, ipFn func(i int) string) []v1beta1.NetworkNeighbor {
		out := make([]v1beta1.NetworkNeighbor, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, v1beta1.NetworkNeighbor{
				Identifier: fmt.Sprintf("%s-%d", dns, i),
				Type:       "external", DNS: dns, DNSNames: []string{dns},
				IPAddress: ipFn(i),
				Ports:     []v1beta1.NetworkPort{{Name: "TCP-443", Protocol: "TCP", Port: ptr.To(int32(443))}},
			})
		}
		return out
	}

	// createNN writes a NetworkNeighborhood with the given egress and returns nothing.
	createNN := func(t *testing.T, nsName, name string, egress []v1beta1.NetworkNeighbor) {
		t.Helper()
		nn := &v1beta1.NetworkNeighborhood{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: nsName,
				Annotations: map[string]string{
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
					helpersv1.CompletionMetadataKey: helpersv1.Full,
				},
			},
			Spec: v1beta1.NetworkNeighborhoodSpec{
				LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
				Containers:    []v1beta1.NetworkNeighborhoodContainer{{Name: "curl", Egress: egress}},
			},
		}
		_, err := storageClient.NetworkNeighborhoods(nsName).Create(ctx, nn, metav1.CreateOptions{})
		require.NoError(t, err, "create NetworkNeighborhood %s", name)
	}

	// pollNN reads the stored NN via the DYNAMIC client (the typed client drops
	// the plural ipAddresses field that exists only on PR#348), re-saving to
	// re-trigger the TTL-cached PreSave collapse, until every wanted substring is
	// present. Returns the last raw JSON and whether all were found; the caller
	// dumps `raw` on failure so the run is self-diagnosing.
	pollNN := func(t *testing.T, nsName, name string, want []string) (string, bool) {
		t.Helper()
		var raw string
		for attempt := 0; attempt < 40; attempt++ {
			got, gErr := dyn.Resource(nnGVR).Namespace(nsName).Get(ctx, name, metav1.GetOptions{})
			if gErr == nil {
				b, _ := json.Marshal(got.Object)
				raw = string(b)
				all := true
				for _, w := range want {
					if !strings.Contains(raw, w) {
						all = false
						break
					}
				}
				if all {
					return raw, true
				}
				_, _ = dyn.Resource(nnGVR).Namespace(nsName).Update(ctx, got, metav1.UpdateOptions{})
			}
			time.Sleep(3 * time.Second)
		}
		return raw, false
	}

	// requireCollapsed polls for `want` and fails with the stored object dumped.
	requireCollapsed := func(t *testing.T, nsName, name string, want []string) string {
		t.Helper()
		raw, ok := pollNN(t, nsName, name, want)
		if !ok {
			t.Logf("stored NetworkNeighborhood %s/%s (expected all of %v):\n%s", nsName, name, want, raw)
			t.Fatalf("network collapse did not produce %v (requires PR#348)", want)
		}
		return raw
	}
	quoted := func(s string) string { return fmt.Sprintf("%q", s) }

	// --- Case 1: S3-style endpoint clustered in one /24 -> single covering /24.
	t.Run("network_single_covering_24", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		createNN(t, ns.Name, "cidr-24", hostGroup("s3.eu-central-1.amazonaws.com.", hostCount,
			func(i int) string { return fmt.Sprintf("52.216.183.%d", i*4) }))
		raw := requireCollapsed(t, ns.Name, "cidr-24", []string{"52.216.183.0/24"})
		for _, last := range []int{4, 120, 200} {
			assert.NotContains(t, raw, quoted(fmt.Sprintf("52.216.183.%d", last)), "host /32 should be collapsed away")
		}
	})

	// --- Case 2: endpoint spanning a whole /16 -> floor /16 (would be /24 buckets by default).
	t.Run("network_floor_16_covering", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		createNN(t, ns.Name, "cidr-16", hostGroup("objects.example-cdn.net.", hostCount,
			func(i int) string { return fmt.Sprintf("100.68.%d.0", i*4) }))
		raw := requireCollapsed(t, ns.Name, "cidr-16", []string{"100.68.0.0/16"})
		for _, third := range []int{4, 120, 200} {
			assert.NotContains(t, raw, quoted(fmt.Sprintf("100.68.%d.0", third)), "host /32 should be collapsed away")
		}
	})

	// --- Case 3: adversarial mix in ONE group — collapsible host /32s alongside a
	// pre-collapsed CIDR, the "*" sentinel, and an IPv6 literal. Hosts must
	// aggregate; the non-aggregatable entries must pass through UNTOUCHED (matches
	// storage's own TestCollapseIPGroups_Idempotent / _IPv6PassThrough).
	t.Run("network_passthrough_cidr_star_ipv6", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		const dns = "mixed.example."
		egress := hostGroup(dns, hostCount, func(i int) string { return fmt.Sprintf("203.0.113.%d", i*4) })
		egress = append(egress,
			v1beta1.NetworkNeighbor{Identifier: "held-cidr", Type: "external", DNS: dns, IPAddresses: []string{"10.9.0.0/16"}},
			v1beta1.NetworkNeighbor{Identifier: "any", Type: "external", DNS: dns, IPAddresses: []string{"*"}},
			v1beta1.NetworkNeighbor{Identifier: "v6", Type: "external", DNS: dns, IPAddress: "2001:db8::1"},
		)
		createNN(t, ns.Name, "cidr-mixed", egress)
		// hosts collapse to /24; held CIDR, "*", and IPv6 survive verbatim.
		raw := requireCollapsed(t, ns.Name, "cidr-mixed",
			[]string{"203.0.113.0/24", "10.9.0.0/16", quoted("*"), "2001:db8::1"})
		for _, last := range []int{4, 120, 200} {
			assert.NotContains(t, raw, quoted(fmt.Sprintf("203.0.113.%d", last)), "aggregatable host /32 should be gone")
		}
	})

	// --- Case 4: DNS plurals + ports are merged/deduped and replicated onto the
	// collapsed CIDR entry (matches TestCollapseIPGroups_MultiBucketReplicatesDNSNamesAndPorts).
	t.Run("network_dns_plurals_replicated", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		egress := make([]v1beta1.NetworkNeighbor, 0, hostCount)
		for i := 0; i < hostCount; i++ {
			egress = append(egress, v1beta1.NetworkNeighbor{
				Identifier: fmt.Sprintf("multi-%d", i),
				Type:       "external", DNS: "multi.example.",
				DNSNames:  []string{"alpha.example.", "beta.example."},
				IPAddress: fmt.Sprintf("198.51.100.%d", i*4),
				Ports: []v1beta1.NetworkPort{
					{Name: "TCP-443", Protocol: "TCP", Port: ptr.To(int32(443))},
					{Name: "TCP-8443", Protocol: "TCP", Port: ptr.To(int32(8443))},
				},
			})
		}
		createNN(t, ns.Name, "cidr-dns", egress)
		// The single collapsed /24 entry must still carry BOTH plural DNS names and BOTH ports.
		requireCollapsed(t, ns.Name, "cidr-dns",
			[]string{"198.51.100.0/24", "alpha.example.", "beta.example.", "8443"})
	})

	// --- Case 5: network collapse and PATH/ENDPOINT collapse under the SAME config
	// must not confuse each other. Realistic inputs only — DNS names are hostnames,
	// never paths; slashes live in endpoint/open paths. Real confusion vectors:
	//   * a DNS WILDCARD subdomain ("*.cdn.example.") — a legit DNS value containing
	//     "*" — must not be confused with the network "*" any-IP sentinel;
	//   * HTTP endpoint paths ("/api/v1/users/<id>") collapse to a dynamic-identifier
	//     wildcard, independently of the network CIDR collapse;
	//   * an IP-shaped OPEN path ("/data/10.0.0.5") stays a literal open, never a CIDR.
	t.Run("network_and_path_no_confusion", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()

		// Network side: 60 hosts -> 192.0.2.0/24. DNSNames carry a real wildcard
		// subdomain (contains "*"). A SEPARATE DNS group carries the network "*"
		// any-IP sentinel in IPAddresses. Both "*"s must survive in their own fields.
		egress := make([]v1beta1.NetworkNeighbor, 0, hostCount+1)
		for i := 0; i < hostCount; i++ {
			egress = append(egress, v1beta1.NetworkNeighbor{
				Identifier: fmt.Sprintf("svc-%d", i), Type: "external",
				DNS: "api.internal.svc.", DNSNames: []string{"api.internal.svc.", "*.cdn.example."},
				IPAddress: fmt.Sprintf("192.0.2.%d", i*4),
				Ports:     []v1beta1.NetworkPort{{Name: "TCP-443", Protocol: "TCP", Port: ptr.To(int32(443))}},
			})
		}
		egress = append(egress, v1beta1.NetworkNeighbor{
			Identifier: "any-ip", Type: "external",
			DNS: "telemetry.example.", DNSNames: []string{"telemetry.example."},
			IPAddresses: []string{"*"},
		})
		createNN(t, ns.Name, "mix-net", egress)

		// Path side: 60 HTTP endpoints differing only by a high-cardinality id
		// segment -> collapse to one ":80/api/v1/users/<DynamicIdentifier>". Plus an
		// IP-shaped OPEN path that must remain a literal open (never a CIDR).
		const ipShapedOpen = "/data/10.0.0.5"
		endpoints := make([]v1beta1.HTTPEndpoint, 0, hostCount)
		for i := 0; i < hostCount; i++ {
			endpoints = append(endpoints, v1beta1.HTTPEndpoint{
				Endpoint: fmt.Sprintf(":80/api/v1/users/%d", i), Methods: []string{"GET"},
			})
		}
		ap := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: "mix-path", Namespace: ns.Name,
				Annotations: map[string]string{
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
					helpersv1.CompletionMetadataKey: helpersv1.Full,
				},
			},
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{{
					Name:      "curl",
					Execs:     []v1beta1.ExecCalls{{Path: "/bin/cat", Args: []string{"/bin/cat"}}},
					Opens:     []v1beta1.OpenCalls{{Path: ipShapedOpen, Flags: []string{"O_RDONLY"}}},
					Endpoints: endpoints,
				}},
			},
		}
		_, err := storageClient.ApplicationProfiles(ns.Name).Create(ctx, ap, metav1.CreateOptions{})
		require.NoError(t, err, "create ApplicationProfile mix-path")

		// Network assertions: hosts collapse to /24; the DNS wildcard subdomain and
		// the "*" any-IP sentinel both survive (distinct fields, not confused). The
		// path wildcard identifier must never appear inside the network object.
		netRaw := requireCollapsed(t, ns.Name, "mix-net",
			[]string{"192.0.2.0/24", "*.cdn.example.", quoted("*")})
		assert.NotContains(t, netRaw, quoted("192.0.2.4"), "network host /32 should be collapsed")
		assert.NotContains(t, netRaw, dynamicpathdetector.DynamicIdentifier, "path wildcard must not leak into the NetworkNeighborhood")

		// Endpoint collapse (typed read): many /users/<id> -> one /users/<DynamicIdentifier>.
		wantEndpoint := ":80/api/v1/users/" + dynamicpathdetector.DynamicIdentifier
		var endpts, openPaths []string
		collapsedEp := false
		for attempt := 0; attempt < 40; attempt++ {
			got, gErr := storageClient.ApplicationProfiles(ns.Name).Get(ctx, "mix-path", metav1.GetOptions{})
			if gErr == nil && len(got.Spec.Containers) > 0 {
				endpts, openPaths = endpts[:0], openPaths[:0]
				for _, e := range got.Spec.Containers[0].Endpoints {
					endpts = append(endpts, e.Endpoint)
				}
				for _, o := range got.Spec.Containers[0].Opens {
					openPaths = append(openPaths, o.Path)
				}
				if slices.Contains(endpts, wantEndpoint) {
					collapsedEp = true
					break
				}
			}
			time.Sleep(3 * time.Second)
		}
		if !collapsedEp {
			t.Logf("stored ApplicationProfile (expected endpoint %s):\n  endpoints=%v\n  opens=%v", wantEndpoint, endpts, openPaths)
			t.Fatalf("HTTP endpoints did not collapse to %s", wantEndpoint)
		}
		assert.NotContains(t, endpts, ":80/api/v1/users/5", "per-id endpoint should have collapsed away")

		// Cross-contamination guards.
		assert.Contains(t, openPaths, ipShapedOpen, "IP-shaped open path must stay a literal path, not a CIDR")
		for _, e := range endpts {
			assert.NotContains(t, e, "192.0.2.0/24", "network CIDR must not leak into an endpoint path")
		}
	})
}
