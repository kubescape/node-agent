package config

import (
	"node-agent/pkg/utils"
	"path"
	"testing"
	"time"
)

func TestIsFalcoEbpfEngineMock(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := true
	actual := config.IsFalcoEbpfEngine()

	if actual != expected {
		t.Errorf("IsFalcoEbpfEngine() returned %v, expected %v", actual, expected)
	}
}

func TestGetFalcoSyscallFilterMockv(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := []string{"open", "openat", "execve", "execveat"}
	actual := config.GetFalcoSyscallFilter()

	if !equalStringSlices(actual, expected) {
		t.Errorf("GetFalcoSyscallFilter() returned %v, expected %v", actual, expected)
	}
}

func TestGetFalcoKernelObjPathMock(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := path.Join(utils.CurrentDir(), "..", "testdata", "mock_falco_ebpf_engine", "kernel_obj_mock.o")
	actual := config.GetFalcoKernelObjPath()

	if actual != expected {
		t.Errorf("GetFalcoKernelObjPath() returned %v, expected %v", actual, expected)
	}
}

func TestGetEbpfEngineLoaderPathMock(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := path.Join(utils.CurrentDir(), "..", "testdata", "mock_falco_ebpf_engine", "userspace_app_mock")
	actual := config.GetEbpfEngineLoaderPath()

	if actual != expected {
		t.Errorf("GetEbpfEngineLoaderPath() returned %v, expected %v", actual, expected)
	}
}

func TestGetUpdateDataPeriodMock(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := time.Duration(120) * time.Second
	actual := config.GetUpdateDataPeriod()

	if actual != expected {
		t.Errorf("GetUpdateDataPeriod() returned %v, expected %v", actual, expected)
	}
}

func TestGetSniffingMaxTimesMock(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := time.Duration(60*60) * time.Second
	actual := config.GetSniffingMaxTimes()

	if actual != expected {
		t.Errorf("GetSniffingMaxTimes() returned %v, expected %v", actual, expected)
	}
}

func TestIsRelevantCVEServiceEnabledMock(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := true
	actual := config.IsRelevantCVEServiceEnabled()

	if actual != expected {
		t.Errorf("IsRelevantCVEServiceEnabled() returned %v, expected %v", actual, expected)
	}
}

func TestGetNodeName(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := "minikube"
	actual := config.GetNodeName()

	if actual != expected {
		t.Errorf("GetNodeName() returned %v, expected %v", actual, expected)
	}
}

func TestGetClusterName(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := "test"
	actual := config.GetClusterName()

	if actual != expected {
		t.Errorf("GetClusterName() returned %v, expected %v", actual, expected)
	}
}

func TestSetNodeName(t *testing.T) {
	config := CreateFalcoMockConfigData()
	config.SetNodeName()

	expected := "minikube"
	actual := config.GetNodeName()

	if actual != expected {
		t.Errorf("SetNodeName() returned %v, expected %v", actual, expected)
	}
}

func TestSetNamespace(t *testing.T) {
	config := CreateFalcoMockConfigData()
	config.SetNamespace()

	expected := "Namespace"
	actual := config.GetNamespace()

	if actual != expected {
		t.Errorf("GetNodeName() returned %v, expected %v", actual, expected)
	}
}

func TestGetNamespace(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := "Namespace"
	actual := config.GetNamespace()

	if actual != expected {
		t.Errorf("GetNamespace() returned %v, expected %v", actual, expected)
	}
}

func TestSetContainerName(t *testing.T) {
	config := CreateFalcoMockConfigData()
	config.SetContainerName()

	expected := "ContName"
	actual := config.GetContainerName()

	if actual != expected {
		t.Errorf("GetContainerName() returned %v, expected %v", actual, expected)
	}
}

func TestGetContainerName(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := "ContName"
	actual := config.GetContainerName()

	if actual != expected {
		t.Errorf("GetContainerName() returned %v, expected %v", actual, expected)
	}
}

func TestSetBackgroundContextURL(t *testing.T) {
	config := CreateFalcoMockConfigData()
	config.SetBackgroundContextURL()

	expected := "URLcontext"
	actual := config.GetBackgroundContextURL()

	if actual != expected {
		t.Errorf("GetBackgroundContextURL() returned %v, expected %v", actual, expected)
	}
}

func TestGetBackgroundContextURL(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := "URLcontext"
	actual := config.GetBackgroundContextURL()

	if actual != expected {
		t.Errorf("GetBackgroundContextURL() returned %v, expected %v", actual, expected)
	}
}

func TestGetAccountID(t *testing.T) {
	config := CreateFalcoMockConfigData()

	expected := "AccountID"
	actual := config.GetAccountID()

	if actual != expected {
		t.Errorf("GetAccountID() returned %v, expected %v", actual, expected)
	}
}
