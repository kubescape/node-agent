package integration

import (
	"os"
	"os/exec"
	"strconv"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
)

// TestS5ReviewV2N4PidAliveFailsClosed (S5 review v2 N4): pidAlive calls a
// process dead only on ESRCH. Any other pidfd_open error (EPERM, EMFILE,
// ENOSYS, ENOMEM) keeps it alive, so its sandbox stays under D10(a). Also:
// this process is alive, a reaped child is dead, and PID 0 is dead.
func TestS5ReviewV2N4PidAliveFailsClosed(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EPERM, unix.EMFILE, unix.ENOSYS, unix.ENOMEM, unix.EINVAL} {
		if !pidAliveWith(func(int, int) (int, error) { return -1, errno }, 1234) {
			t.Fatalf("pidfd_open %v was taken as dead", errno)
		}
	}
	if pidAliveWith(func(int, int) (int, error) { return -1, unix.ESRCH }, 1234) {
		t.Fatal("ESRCH was taken as alive")
	}
	if !pidAlive(uint32(os.Getpid())) {
		t.Fatal("this process is not alive")
	}
	child := exec.Command("/bin/true")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	if pidAlive(uint32(child.Process.Pid)) {
		// Only a reuse of the PID in between may make it alive.
		if _, err := os.Stat("/proc/" + strconv.Itoa(child.Process.Pid)); err != nil {
			t.Fatalf("reaped child %d taken as alive: %v", child.Process.Pid, err)
		}
		t.Logf("PID %d was reused before the check", child.Process.Pid)
	} else {
		t.Logf("reaped child %d: dead", child.Process.Pid)
	}
	n := &nriGate{alive: pidAlive}
	if n.PauseAlive(&nriapi.PodSandbox{Pid: 0}) || !n.PauseAlive(&nriapi.PodSandbox{Pid: uint32(os.Getpid())}) {
		t.Fatal("PauseAlive")
	}
}
