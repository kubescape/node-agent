package ebpfeng

import (
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
}
