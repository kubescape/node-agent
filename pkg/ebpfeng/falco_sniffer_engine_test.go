package ebpfeng

import (
	"os"
	"path"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"
	"sniffer/pkg/utils"
	"strings"
	"testing"
)

func TestConvertStringTimeToTimeOBJ(t *testing.T) {
	timestamp := "2023-02-14T14:30:06.863996608+0000"
	ti, err := convertStringTimeToTimeOBJ(timestamp)
	if err != nil {
		t.Fatalf("TestConvertStringTimeToTimeOBJ failed with err %v", err)
	}
	if ti.Year() != 2023 {
		t.Fatalf("timestamp convert Year is wrong")
	}
	if ti.Day() != 14 {
		t.Fatalf("timestamp convert day is wrong")
	}
	if ti.Hour() != 14 {
		t.Fatalf("timestamp convert hour is wrong")
	}
	if ti.Minute() != 30 {
		t.Fatalf("timestamp convert minute is wrong")
	}
	if ti.Second() != 6 {
		t.Fatalf("timestamp convert second is wrong")
	}
	if ti.Nanosecond() != 863996608 {
		t.Fatalf("timestamp convert nanosecond is wrong")
	}

	timestamp = "2w023-02-14T14:30:06.863996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

	timestamp = "2023-0w2-14T14:30:06.863996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

	timestamp = "2023-02-1w4T14:30:06.863996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

	timestamp = "2023-02-14T1w4:30:06.863996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

	timestamp = "2023-02-14T14:3w0:06.863996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

	timestamp = "2023-02-14T14:30:0w6.863996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

	timestamp = "2023-02-14T14:30:06.86w3996608+0000"
	_, err = convertStringTimeToTimeOBJ(timestamp)
	if err == nil {
		t.Fatalf("timestamp convert should fail")
	}

}

func TestParseFalcoEvent(t *testing.T) {

	line := "2023-02-14T14:30:06.863996608+0000]::[0002f88945ec]::[CAT=FILE]::[PPID=3006]::[PID=4525]::[TYPE=openat(fd: <f>/var/lib/kubelet/pods, dirfd: AT_FDCWD, name: /var/lib/kubelet/pods, flags: O_RDONLY|O_CLOEXEC, mode: 0, dev: 802, ino: 6456368)]::[EXE=/var/lib/minikube/binaries/v1.24.3/kubelet]::[CMD="
	ev, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine failed with err %v", err)
	}

	if ev.GetEventContainerID() != "0002f88945ec" {
		t.Fatalf("ev.GetEventContainerID() failed")
	}

	if ev.GetEventSyscallArgs() != "TYPE=openat(fd: <f>/var/lib/kubelet/pods, dirfd: AT_FDCWD, name: /var/lib/kubelet/pods, flags: O_RDONLY|O_CLOEXEC, mode: 0, dev: 802, ino: 6456368)" {
		t.Fatalf("ev.GetEventContainerID() failed")
	}

	line = "drop event occured"
	ev, err = parseLine(line)
	if err != nil {
		t.Fatalf("drop event: parseLine failed with err %v", err)
	}

	if !strings.Contains(ev.GetEventCMD(), "drop event occurred") {
		t.Fatalf("drop event should contain line: %s in cmd", line)
	}

	line = "2023-02-14T14:30:06.863996608+0000]::[0002f88945ec]::"
	_, err = parseLine(line)
	if err == nil {
		t.Fatalf("parse line should fail")
	}

	line = "2023-02-14T14:]::[0002f88945ec]::[CAT=FILE]::[PPID=3006]::[PID=4525]::[TYPE=openat(fd: <f>/var/lib/kubelet/pods, dirfd: AT_FDCWD, name: /var/lib/kubelet/pods, flags: O_RDONLY|O_CLOEXEC, mode: 0, dev: 802, ino: 6456368)]::[EXE=/var/lib/minikube/binaries/v1.24.3/kubelet]::[CMD="
	_, err = parseLine(line)
	if err == nil {
		t.Fatalf("parse line should fail")
	}

}

func TestCreateSyscallFilterString(t *testing.T) {
	expectedFilterString := "evt.type=execve or evt.type=open"
	filterString := createSyscallFilterString([]string{"execve", "open"})

	if filterString != expectedFilterString {
		t.Fatalf("filterString:%s should be equal to expectedFilterString:%s", filterString, expectedFilterString)
	}

}

func TestCreateFalcoEbpfEngine(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(config.ConfigEnvVar, configPath)
	if err != nil {
		t.Fatalf("failed to set env %s with err %v", config.ConfigEnvVar, err)
	}

	config := config.GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	engine := CreateFalcoEbpfEngine([]string{"123", "456"}, false, false, "")
	if engine.containerID != "" || engine.includeHost != false || engine.sniffMainThreadOnly != false {
		t.Fatalf("CreateFalcoEbpfEngine fail to create as expected")
	}
}

func TestEbpfEngineCMDWithParams(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(config.ConfigEnvVar, configPath)
	if err != nil {
		t.Fatalf("failed to set env %s with err %v", config.ConfigEnvVar, err)
	}

	config := config.GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	engine := CreateFalcoEbpfEngine([]string{"123", "456"}, false, false, "")
	if engine.containerID != "" || engine.includeHost != false || engine.sniffMainThreadOnly != false {
		t.Fatalf("CreateFalcoEbpfEngine fail to create as expected")
	}

	cmd := engine.ebpfEngineCMDWithParams()
	if cmd[0] != "-f" || cmd[1] != "evt.type=123 or evt.type=456" || cmd[2] != "-e" {
		t.Fatalf("ebpfEngineCMDWithParams is note with the right values %v", cmd)
	}

	engine2 := CreateFalcoEbpfEngine([]string{"123", "456"}, true, true, "123")
	if engine2.containerID != "123" || engine2.includeHost != true || engine2.sniffMainThreadOnly != true {
		t.Fatalf("CreateFalcoEbpfEngine fail to create as expected")
	}

	cmd2 := engine2.ebpfEngineCMDWithParams()
	if cmd2[0] != "-f" || cmd2[1] != "evt.type=123 or evt.type=456" || cmd2[2] != "-o" || cmd2[3] != "-m" || cmd2[4] != "-c" || cmd2[5] != "123" || cmd2[6] != "-e" {
		t.Fatalf("ebpfEngineCMDWithParams is note with the right values %v", cmd)
	}

}

func TestStartEbpfEngine(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(config.ConfigEnvVar, configPath)
	if err != nil {
		t.Fatalf("failed to set env ConfigEnvVar with err %v", err)
	}

	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Fatalf("GetConfigurationReader failed with err %v", err)
	}
	err = cfg.ParseConfiguration(v1.CreateFalcoMockConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	engine := CreateFalcoEbpfEngine([]string{"123", "456"}, false, false, "")
	if engine.containerID != "" || engine.includeHost != false || engine.sniffMainThreadOnly != false {
		t.Fatalf("CreateFalcoEbpfEngine fail to create as expected")
	}

	cmd := engine.ebpfEngineCMDWithParams()
	if cmd[0] != "-f" || cmd[1] != "evt.type=123 or evt.type=456" || cmd[2] != "-e" {
		t.Fatalf("ebpfEngineCMDWithParams is note with the right values %v", cmd)
	}

	err = engine.StartEbpfEngine()
	if err != nil {
		t.Fatalf("StartEbpfEngine failed with err %v", err)
	}
}
