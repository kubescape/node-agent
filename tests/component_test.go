//go:build component

package tests

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1client "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

	// Malicious activity will be detected in 3 minutes + X seconds to wait for the alerts to be generated
	maliciousAppWaitBeforeStart := time.Minute * 3
	waitBeforeLookingForAlerts := time.Minute * 2
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

	// invalid fields
	file := ruleBindingPath("invalid-name.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("invalid-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("invalid-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	// duplicate fields
	file = ruleBindingPath("dup-fields-name-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-name-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-id-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)
}

// TODO: create a test with an existing app profile and check if the alerts are generated
//func Test_08_BasicAlertTestExistingProfile(t *testing.T) {
//
//}

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

// func Test_10_DemoTest(t *testing.T) {
// 	start := time.Now()
// 	defer tearDownTest(t, start)

// 	//testutils.IncreaseNodeAgentSniffingTime("2m")
// 	wl, err := testutils.NewTestWorkload("default", path.Join(utils.CurrentDir(), "resources/ping-app-role.yaml"))
// 	if err != nil {
// 		t.Errorf("Error creating role: %v", err)
// 	}

// 	wl, err = testutils.NewTestWorkload("default", path.Join(utils.CurrentDir(), "resources/ping-app-role-binding.yaml"))
// 	if err != nil {
// 		t.Errorf("Error creating role binding: %v", err)
// 	}

// 	wl, err = testutils.NewTestWorkload("default", path.Join(utils.CurrentDir(), "resources/ping-app-service.yaml"))
// 	if err != nil {
// 		t.Errorf("Error creating service: %v", err)
// 	}

// 	wl, err = testutils.NewTestWorkload("default", path.Join(utils.CurrentDir(), "resources/ping-app.yaml"))
// 	if err != nil {
// 		t.Errorf("Error creating workload: %v", err)
// 	}
// 	assert.NoError(t, wl.WaitForReady(80))
// 	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4"}, "")
// 	err = wl.WaitForApplicationProfileCompletion(80)
// 	if err != nil {
// 		t.Errorf("Error waiting for application profile to be completed: %v", err)
// 	}
// 	// err = wl.WaitForNetworkNeighborhoodCompletion(80)
// 	// if err != nil {
// 	// 	t.Errorf("Error waiting for network neighborhood to be completed: %v", err)
// 	// }

// 	// Do a ls command using command injection in the ping command
// 	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4;ls"}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	// Do a cat command using command injection in the ping command
// 	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4;cat /run/secrets/kubernetes.io/serviceaccount/token"}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	// Do an uname command using command injection in the ping command
// 	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4;uname -m | sed 's/x86_64/amd64/g' | sed 's/aarch64/arm64/g'"}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	// Download kubectl
// 	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4;curl -LO \"https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl\""}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	// Sleep for 10 seconds to wait for the kubectl download
// 	time.Sleep(10 * time.Second)

// 	// Make kubectl executable
// 	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4;chmod +x kubectl"}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	// Get the pods in the cluster
// 	output, _, err := wl.ExecIntoPod([]string{"sh", "-c", "ping 1.1.1.1 -c 4;./kubectl --server https://kubernetes.default --insecure-skip-tls-verify --token $(cat /run/secrets/kubernetes.io/serviceaccount/token) get pods"}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	// Check that the output contains the pod-ping-app pod
// 	assert.Contains(t, output, "ping-app", "Expected output to contain 'ping-app'")

// 	// Get the alerts and check that the alerts are generated
// 	alerts, err := testutils.GetAlerts(wl.Namespace)
// 	if err != nil {
// 		t.Errorf("Error getting alerts: %v", err)
// 	}

// 	// Validate that all alerts are signaled
// 	expectedAlerts := map[string]bool{
// 		"Unexpected process launched": false,
// 		"Unexpected file access":      false,
// 		"Kubernetes Client Executed":  false,
// 		// "Exec from malicious source":               false,
// 		"Exec Binary Not In Base Image":           false,
// 		"Unexpected Service Account Token Access": false,
// 		// "Unexpected domain request":               false,
// 	}

// 	for _, alert := range alerts {
// 		ruleName, ruleOk := alert.Labels["rule_name"]
// 		if ruleOk {
// 			if _, exists := expectedAlerts[ruleName]; exists {
// 				expectedAlerts[ruleName] = true
// 			}
// 		}
// 	}

// 	for ruleName, signaled := range expectedAlerts {
// 		if !signaled {
// 			t.Errorf("Expected alert '%s' was not signaled", ruleName)
// 		}
// 	}
// }

// func Test_11_DuplicationTest(t *testing.T) {
// 	start := time.Now()
// 	defer tearDownTest(t, start)

// 	ns := testutils.NewRandomNamespace()
// 	// wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
// 	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/ping-app.yaml"))
// 	if err != nil {
// 		t.Errorf("Error creating workload: %v", err)
// 	}
// 	assert.NoError(t, wl.WaitForReady(80))

// 	err = wl.WaitForApplicationProfileCompletion(80)
// 	if err != nil {
// 		t.Errorf("Error waiting for application profile to be completed: %v", err)
// 	}

// 	// process launched from nginx container
// 	_, _, err = wl.ExecIntoPod([]string{"ls", "-a"}, "ping-app")
// 	if err != nil {
// 		t.Errorf("Error executing remote command: %v", err)
// 	}

// 	time.Sleep(20 * time.Second)

// 	alerts, err := testutils.GetAlerts(wl.Namespace)
// 	if err != nil {
// 		t.Errorf("Error getting alerts: %v", err)
// 	}

// 	// Validate that unexpected process launched alert is signaled only once
// 	count := 0
// 	for _, alert := range alerts {
// 		ruleName, ruleOk := alert.Labels["rule_name"]
// 		if ruleOk {
// 			if ruleName == "Unexpected process launched" {
// 				count++
// 			}
// 		}
// 	}

// 	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "ping-app")

// 	assert.Equal(t, 1, count, "Expected 1 alert of type 'Unexpected process launched' but got %d", count)
// }
