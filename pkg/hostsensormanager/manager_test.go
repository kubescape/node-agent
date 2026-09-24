package hostsensormanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/hostsensor"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func sensorKinds(sensors []Sensor) []string {
	kinds := make([]string, 0, len(sensors))
	for _, s := range sensors {
		kinds = append(kinds, s.GetKind())
	}
	return kinds
}

func TestFilterSensors(t *testing.T) {
	sensors := newSensors("test-node")
	all := []string{"OsReleaseFile", "KernelVersion", "LinuxSecurityHardeningStatus", "OpenPortsList", "LinuxKernelVariables", "KubeletInfo", "KubeProxyInfo", "ControlPlaneInfo", "CloudProviderInfo", "CNIInfo"}
	require.Equal(t, all, sensorKinds(sensors))
	for _, tt := range []struct {
		name           string
		excluded, want []string
	}{
		{"default", nil, all},
		{"empty", []string{}, all},
		{"kube-proxy", []string{"KubeProxyInfo"}, append(append([]string{}, all[:6]...), all[7:]...)},
		{"duplicates", []string{"KubeProxyInfo", "KubeProxyInfo"}, append(append([]string{}, all[:6]...), all[7:]...)},
		{"multiple", []string{"KubeProxyInfo", "CNIInfo"}, append(append([]string{}, all[:6]...), all[7:9]...)},
		{"all", all, []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, ValidateExcludedSensors(tt.excluded))
			got, err := filterSensors(sensors, tt.excluded)
			require.NoError(t, err)
			require.Equal(t, tt.want, sensorKinds(got))
			require.Equal(t, all, sensorKinds(sensors), "filter must not mutate the original registration list")
		})
	}
	for _, invalid := range []string{"", "kubeproxyinfo", "KubeProxy", " KubeProxyInfo"} {
		t.Run("invalid/"+invalid, func(t *testing.T) {
			require.EqualError(t, ValidateExcludedSensors([]string{invalid}), fmt.Sprintf("unknown excluded host sensor %q; valid sensors: %s", invalid, strings.Join(all, ", ")))
			_, err := filterSensors(sensors, []string{invalid})
			require.EqualError(t, err, fmt.Sprintf("unknown excluded host sensor %q; valid sensors: %s", invalid, strings.Join(all, ", ")))
		})
	}
}

func TestHostSensorExclusionValidationBeforeClient(t *testing.T) {
	// Without in-cluster settings a valid configuration reaches client initialization and fails.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	_, err := NewHostSensorManager(Config{Enabled: true, NodeName: "test-node", ExcludedSensors: []string{"typo"}})
	require.ErrorContains(t, err, `unknown excluded host sensor "typo"`)
	_, err = NewHostSensorManager(Config{Enabled: true, NodeName: "test-node", ExcludedSensors: []string{"KubeProxyInfo"}})
	require.ErrorContains(t, err, "failed to create CRD client")
	disabled, err := NewHostSensorManager(Config{ExcludedSensors: []string{"typo"}})
	require.NoError(t, err)
	require.IsType(t, &noopManager{}, disabled)
}

type countingSensor struct {
	kind  hostsensor.HostSensorResource
	calls int
	err   error
}

func (s *countingSensor) GetKind() string       { return string(s.kind) }
func (s *countingSensor) GetPluralKind() string { return hostsensor.MapResourceToPlural(s.kind) }
func (s *countingSensor) Sense() (any, error) {
	s.calls++
	return map[string]any{"nodeName": "test-node", "content": fmt.Sprint(s.calls)}, s.err
}

func captureSensorLogs(t *testing.T) string {
	t.Helper()
	previous := logger.L()
	name, level, writer := previous.LoggerName(), previous.GetLevel(), previous.GetWriter()
	logFile, err := os.CreateTemp(t.TempDir(), "sensor-logs")
	require.NoError(t, err)
	logger.InitLogger("pretty")
	logger.L().SetWriter(logFile)
	require.NoError(t, logger.L().SetLevel("warning"))
	t.Cleanup(func() {
		logger.InitLogger(name)
		_ = logger.L().SetLevel(level)
		if writer != nil {
			logger.L().SetWriter(writer)
		}
		_ = logFile.Close()
	})
	return logFile.Name()
}

func TestRunSensingExcludedKubeProxy(t *testing.T) {
	logPath := captureSensorLogs(t)
	before := &countingSensor{kind: hostsensor.OsReleaseFile}
	proxy := &countingSensor{kind: hostsensor.KubeProxyInfo, err: errors.New("kube-proxy process absent")}
	failing := &countingSensor{kind: hostsensor.KubeletInfo, err: errors.New("real kubelet failure")}
	after := &countingSensor{kind: hostsensor.CNIInfo}
	sensors, err := filterSensors([]Sensor{before, proxy, failing, after}, []string{"KubeProxyInfo"})
	require.NoError(t, err)
	// Seed the failed sensor so UpdateStatus exercises its normal successful patch path.
	failedObject := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": HostDataGroup + "/" + HostDataVersion, "kind": failing.GetKind(),
		"metadata": map[string]any{"name": "test-node"},
	}}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), failedObject)
	m := &manager{sensors: sensors, crdClient: &CRDClient{dynamicClient: client, nodeName: "test-node"}}
	for pass := 1; pass <= 3; pass++ {
		client.ClearActions()
		m.runSensing(context.Background())
		require.Zero(t, proxy.calls)
		for _, peer := range []*countingSensor{before, failing, after} {
			require.Equal(t, pass, peer.calls)
		}
		for _, action := range client.Actions() {
			require.NotEqual(t, proxy.GetPluralKind(), action.GetResource().Resource)
		}
		for _, peer := range []*countingSensor{before, after} {
			gvr := schema.GroupVersionResource{Group: HostDataGroup, Version: HostDataVersion, Resource: peer.GetPluralKind()}
			obj, err := client.Resource(gvr).Get(context.Background(), "test-node", metav1.GetOptions{})
			require.NoError(t, err)
			content, _, err := unstructured.NestedString(obj.Object, "spec", "content")
			require.NoError(t, err)
			require.Equal(t, fmt.Sprint(pass), content)
		}
	}
	failedGVR := schema.GroupVersionResource{Group: HostDataGroup, Version: HostDataVersion, Resource: failing.GetPluralKind()}
	failed, err := client.Resource(failedGVR).Get(context.Background(), "test-node", metav1.GetOptions{})
	require.NoError(t, err)
	failure, _, err := unstructured.NestedString(failed.Object, "status", "error")
	require.NoError(t, err)
	require.Equal(t, "real kubelet failure", failure)
	logs, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotContains(t, string(logs), "KubeProxyInfo")
	require.Equal(t, 3, strings.Count(string(logs), "sensor failed"))
	require.Equal(t, 3, strings.Count(string(logs), "real kubelet failure"))
	require.NotContains(t, string(logs), "failed to update CRD status")
}

func TestAllHostSensorsExcluded(t *testing.T) {
	sensors := newSensors("test-node")
	filtered, err := filterSensors(sensors, sensorKinds(sensors))
	require.NoError(t, err)
	require.Empty(t, filtered)
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	m := &manager{config: Config{NodeName: "test-node", Interval: time.Hour}, sensors: filtered,
		crdClient: &CRDClient{dynamicClient: client, nodeName: "test-node"}, stopCh: make(chan struct{})}
	require.NoError(t, m.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	m.runSensing(context.Background())
	require.NoError(t, m.Stop())
	require.Empty(t, client.Actions())
}
