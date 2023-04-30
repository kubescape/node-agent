package config

import (
	"testing"
	"time"
)

func TestIsFalcoEbpfEngine(t *testing.T) {
	c := CreateConfigData()
	if c.IsFalcoEbpfEngine() {
		t.Errorf("Expected false, got true")
	}

	c.FalcoEbpfEngineData.EbpfEngineLoaderPath = "/path/to/loader"
	c.FalcoEbpfEngineData.KernelObjPath = "/path/to/loader"
	if !c.IsFalcoEbpfEngine() {
		t.Errorf("Expected true, got false")
	}
}

func TestSetFalcoSyscallFilter(t *testing.T) {
	c := CreateConfigData()
	c.FeatureList = []SnifferServices{
		{Name: "relevantCVEs"},
		{Name: "otherService"},
	}
	c.setFalcoSyscallFilter()
	if len(falcoSyscallFilter) != 0 {
		t.Errorf("Expected empty list")
	}

	c.FalcoEbpfEngineData.EbpfEngineLoaderPath = "/path/to/loader"
	c.FalcoEbpfEngineData.KernelObjPath = "/path/to/loader"
	c.setFalcoSyscallFilter()
	expected := []string{"open", "openat", "execve", "execveat"}
	if !equalStringSlices(falcoSyscallFilter, expected) {
		t.Errorf("Expected %v, got %v", expected, falcoSyscallFilter)
	}

}

func TestGetFalcoSyscallFilter(t *testing.T) {
	c := CreateConfigData()
	c.FeatureList = []SnifferServices{
		{Name: "relevantCVEs"},
		{Name: "otherService"},
	}

	filter := c.GetFalcoSyscallFilter()
	expected := []string{"open", "openat", "execve", "execveat"}
	if !equalStringSlices(filter, expected) {
		t.Errorf("Expected %v, got %v", expected, filter)
	}

	// Ensure that the filter is cached
	falcoSyscallFilter = []string{"other", "syscall"}
	filter = c.GetFalcoSyscallFilter()
	if !equalStringSlices(filter, []string{"other", "syscall"}) {
		t.Errorf("Expected [other syscall], got %v", filter)
	}
}

func TestGetFalcoKernelObjPath(t *testing.T) {
	c := CreateConfigData()
	c.FalcoEbpfEngineData.KernelObjPath = "/path/to/kernel/obj"
	if path := c.GetFalcoKernelObjPath(); path != "/path/to/kernel/obj" {
		t.Errorf("Expected /path/to/kernel/obj, got %v", path)
	}
}

func TestGetEbpfEngineLoaderPath(t *testing.T) {
	c := CreateConfigData()
	c.FalcoEbpfEngineData.EbpfEngineLoaderPath = "/path/to/loader"
	if path := c.GetEbpfEngineLoaderPath(); path != "/path/to/loader" {
		t.Errorf("Expected /path/to/loader, got %v", path)
	}
}

func TestGetUpdateDataPeriod(t *testing.T) {
	c := CreateConfigData()
	c.DB.UpdateDataPeriod = 1
	if dur := c.GetUpdateDataPeriod(); dur != 1*time.Minute {
		t.Errorf("Expected 60s, got %v", dur)
	}
}

func TestGetSniffingMaxTimes(t *testing.T) {
	c := CreateConfigData()
	c.SnifferData.SniffingMaxTime = 5
	if dur := c.GetSniffingMaxTimes(); dur != 5*time.Minute {
		t.Errorf("Expected 5m, got %v", dur)
	}
}

func TestIsRelevantCVEServiceEnabled(t *testing.T) {
	c := CreateConfigData()
	if c.IsRelevantCVEServiceEnabled() {
		t.Errorf("Expected true, got false")
	}

	c.FeatureList = []SnifferServices{
		{Name: "relevantCVEs"},
		{Name: "otherService"},
	}

	if !c.IsRelevantCVEServiceEnabled() {
		t.Errorf("Expected true, got false")
	}

}

func TestConfigData_GetNodeName(t *testing.T) {
	expectedName := "node-1"
	c := &ConfigData{
		NodeData: NodeData{Name: expectedName},
	}
	if c.GetNodeName() != expectedName {
		t.Errorf("GetNodeName() returned %s, expected %s", c.GetNodeName(), expectedName)
	}
}

func TestConfigData_GetClusterName(t *testing.T) {
	expectedName := "cluster-1"
	c := &ConfigData{
		ClusterName: expectedName,
	}
	if c.GetClusterName() != expectedName {
		t.Errorf("GetClusterName() returned %s, expected %s", c.GetClusterName(), expectedName)
	}
}

func TestConfigData_SetNodeName(t *testing.T) {
	expectedName := "node-1"
	t.Setenv(nodeNameEnvVar, expectedName)
	c := &ConfigData{}
	c.SetNodeName()
	if c.NodeData.Name != expectedName {
		t.Errorf("SetNodeName() failed to set the node name to %s, got %s instead", expectedName, c.NodeData.Name)
	}
}

func TestConfigData_SetNamespace(t *testing.T) {
	expectedName := "namespace-1"
	t.Setenv(NamespaceEnvVar, expectedName)
	c := &ConfigData{}
	c.SetNamespace()
	if c.Namespace != expectedName {
		t.Errorf("SetNamespace() failed to set the namespace to %s, got %s instead", expectedName, c.Namespace)
	}
}

func TestConfigData_SetContainerName(t *testing.T) {
	expectedName := "cont-1"
	t.Setenv(ContainerNameEnvVar, expectedName)
	c := &ConfigData{}
	c.SetContainerName()
	if c.ContainerName != expectedName {
		t.Errorf("SetContainerName() failed to set the container name to %s, got %s instead", expectedName, c.ContainerName)
	}
}

func TestConfigData_SetBackgroundContextURL(t *testing.T) {
	expectedName := "URL-1"
	t.Setenv("OTEL_COLLECTOR_SVC", expectedName)
	c := &ConfigData{}
	c.SetBackgroundContextURL()
	if c.telemetryURL != expectedName {
		t.Errorf("SetBackgroundContextURL() failed to set the background context name to %s, got %s instead", expectedName, c.telemetryURL)
	}
}

func TestConfigData_GetNamespace(t *testing.T) {
	expectedName := ""
	c := &ConfigData{}
	if c.GetNamespace() != expectedName {
		t.Errorf("GetNamespace() failed to get the namespace to %s, got %s instead", expectedName, c.Namespace)
	}
}

func TestConfigData_GetContainerName(t *testing.T) {
	expectedName := ""
	c := &ConfigData{}
	if c.GetContainerName() != expectedName {
		t.Errorf("GetContainerName() failed to set the container name to %s, got %s instead", expectedName, c.NodeData.Name)
	}
}

func TestConfigData_GetBackgroundContextURL(t *testing.T) {
	expectedName := ""
	c := &ConfigData{}
	if c.GetBackgroundContextURL() != expectedName {
		t.Errorf("GetBackgroundContextURL() failed to get the background context name to %s, got %s instead", expectedName, c.NodeData.Name)
	}
}

func TestConfigData_GetAccountID(t *testing.T) {
	expectedName := ""
	c := &ConfigData{}
	if c.GetAccountID() != expectedName {
		t.Errorf("GetAccountID() failed to get the account ID name to %s, got %s instead", expectedName, c.NodeData.Name)
	}
}

// check is slices are equal
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
