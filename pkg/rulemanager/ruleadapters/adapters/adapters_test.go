package adapters

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	iouringsyscall "github.com/iceber/iouring-go/syscall"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAdapter_SetFailureMetadata(t *testing.T) {
	adapter := NewOpenAdapter()
	failure := &types.GenericRuleFailure{}

	// Non-matching event type is ignored
	adapter.SetFailureMetadata(failure, &events.EnrichedEvent{Event: &events.ProcfsEvent{}}, nil)
	assert.Empty(t, failure.GetBaseRuntimeAlert().InfectedPID)

	ev := &utils.StructEvent{
		Pid:         101,
		Comm:        "cat",
		FullPath:    "/etc/shadow",
		Flags:       []string{"O_RDONLY"},
		ContainerID: "cid-open",
		Pod:         "pod-open",
		Extra:       "extra-open",
	}
	adapter.SetFailureMetadata(failure, &events.EnrichedEvent{Event: ev}, nil)

	alert := failure.GetBaseRuntimeAlert()
	assert.Equal(t, uint32(101), alert.InfectedPID)
	assert.Equal(t, "/etc/shadow", alert.Arguments["path"])
	assert.Equal(t, []string{"O_RDONLY"}, alert.Arguments["flags"])
	require.NotNil(t, alert.Identifiers)
	assert.Equal(t, "cat", alert.Identifiers.Process.Name)
	assert.Equal(t, filepath.Base("/etc/shadow"), alert.Identifiers.File.Name)
	assert.Equal(t, filepath.Dir("/etc/shadow"), alert.Identifiers.File.Directory)
	assert.Equal(t, "cid-open", failure.GetRuntimeProcessDetails().ContainerID)
	assert.Equal(t, "pod-open", failure.GetRuntimeAlertK8sDetails().PodName)
	assert.Equal(t, "extra-open", failure.GetExtra())
}

func TestCapabilitiesAdapter_SetFailureMetadata(t *testing.T) {
	adapter := NewCapabilitiesAdapter()
	failure := &types.GenericRuleFailure{}

	ev := &utils.StructEvent{
		Pid:         202,
		Comm:        "capsh",
		Syscall:     "capset",
		CapName:     "CAP_SYS_ADMIN",
		ContainerID: "cid-cap",
		Pod:         "pod-cap",
	}
	adapter.SetFailureMetadata(failure, &events.EnrichedEvent{Event: ev}, nil)

	alert := failure.GetBaseRuntimeAlert()
	assert.Equal(t, uint32(202), alert.InfectedPID)
	assert.Equal(t, "capset", alert.Arguments["syscall"])
	assert.Equal(t, "CAP_SYS_ADMIN", alert.Arguments["capability"])
	require.NotNil(t, alert.Identifiers)
	assert.Equal(t, "capsh", alert.Identifiers.Process.Name)
	assert.Equal(t, "cid-cap", failure.GetRuntimeProcessDetails().ContainerID)
	assert.Equal(t, "pod-cap", failure.GetRuntimeAlertK8sDetails().PodName)
}

func TestSymlinkAndHardlinkAdapters_SetFailureMetadata(t *testing.T) {
	ev := &utils.StructEvent{
		Pid:         303,
		Ppid:        1,
		Comm:        "ln",
		ExePath:     "/bin/ln",
		OldPath:     "/etc/passwd",
		NewPath:     "/tmp/passwd-link",
		UpperLayer:  true,
		ContainerID: "cid-link",
		Pod:         "pod-link",
		PodLabels:   map[string]string{"app": "test"},
	}

	symFailure := &types.GenericRuleFailure{}
	NewSymlinkAdapter().SetFailureMetadata(symFailure, &events.EnrichedEvent{Event: ev}, nil)
	symAlert := symFailure.GetBaseRuntimeAlert()
	assert.Equal(t, uint32(303), symAlert.InfectedPID)
	assert.Equal(t, "/etc/passwd", symAlert.Arguments["oldPath"])
	assert.Equal(t, "/tmp/passwd-link", symAlert.Arguments["newPath"])
	assert.Equal(t, filepath.Base("/etc/passwd"), symAlert.Identifiers.File.Name)
	assert.Equal(t, "pod-link", symFailure.GetRuntimeAlertK8sDetails().PodName)

	hardFailure := &types.GenericRuleFailure{}
	NewHardlinkAdapter().SetFailureMetadata(hardFailure, &events.EnrichedEvent{Event: ev}, nil)
	hardAlert := hardFailure.GetBaseRuntimeAlert()
	assert.Equal(t, uint32(303), hardAlert.InfectedPID)
	assert.Equal(t, "/etc/passwd", hardAlert.Arguments["oldPath"])
	assert.Equal(t, "/tmp/passwd-link", hardAlert.Arguments["newPath"])
	assert.Equal(t, "/bin/ln", hardFailure.GetRuntimeProcessDetails().ProcessTree.Path)
}

func TestBpfKmodUnshareSyscallAdapters_SetFailureMetadata(t *testing.T) {
	ev := &utils.StructEvent{
		Pid:         404,
		Ppid:        10,
		Comm:        "insmod",
		Pcomm:       "bash",
		ExePath:     "/sbin/insmod",
		Cmd:         5,
		AttrSize:    128,
		Module:      "evil_mod",
		Syscall:     "init_module",
		UpperLayer:  true,
		ContainerID: "cid-kern",
		Pod:         "pod-kern",
	}

	bpfFailure := &types.GenericRuleFailure{}
	NewBpfAdapter().SetFailureMetadata(bpfFailure, &events.EnrichedEvent{Event: ev}, nil)
	assert.Equal(t, uint32(5), bpfFailure.GetBaseRuntimeAlert().Arguments["cmd"])
	assert.Equal(t, uint32(128), bpfFailure.GetBaseRuntimeAlert().Arguments["attrSize"])
	assert.Equal(t, "/sbin/insmod", bpfFailure.GetBaseRuntimeAlert().Arguments["exePath"])

	kmodFailure := &types.GenericRuleFailure{}
	NewKmodAdapter().SetFailureMetadata(kmodFailure, &events.EnrichedEvent{Event: ev}, nil)
	assert.Equal(t, "evil_mod", kmodFailure.GetBaseRuntimeAlert().Arguments["module"])
	assert.Equal(t, "init_module", kmodFailure.GetBaseRuntimeAlert().Arguments["syscall"])

	unshareFailure := &types.GenericRuleFailure{}
	NewUnshareAdapter().SetFailureMetadata(unshareFailure, &events.EnrichedEvent{Event: ev}, nil)
	assert.Equal(t, "/sbin/insmod", unshareFailure.GetBaseRuntimeAlert().Arguments["exePath"])
	assert.Equal(t, "insmod", unshareFailure.GetBaseRuntimeAlert().Identifiers.Process.Name)

	syscallFailure := &types.GenericRuleFailure{}
	NewSyscallAdapter().SetFailureMetadata(syscallFailure, &events.EnrichedEvent{Event: ev}, nil)
	assert.Equal(t, "init_module", syscallFailure.GetBaseRuntimeAlert().Arguments["syscall"])
	assert.Equal(t, uint32(404), syscallFailure.GetBaseRuntimeAlert().InfectedPID)
}

func TestSSHHTTPAndIoUringAdapters_SetFailureMetadata(t *testing.T) {
	sshEv := &utils.StructEvent{
		Pid:         505,
		Comm:        "ssh",
		SrcIP:       "10.0.0.1",
		DstIP:       "10.0.0.2",
		SrcPort:     54321,
		DstPort:     22,
		ContainerID: "cid-ssh",
		Pod:         "pod-ssh",
	}
	sshFailure := &types.GenericRuleFailure{}
	NewSSHAdapter().SetFailureMetadata(sshFailure, &events.EnrichedEvent{Event: sshEv}, nil)
	sshAlert := sshFailure.GetBaseRuntimeAlert()
	assert.Equal(t, "10.0.0.1", sshAlert.Arguments["src_ip"])
	assert.Equal(t, "10.0.0.2", sshAlert.Arguments["dst_ip"])
	assert.Equal(t, uint16(22), sshAlert.Arguments["dst_port"])
	require.NotNil(t, sshAlert.Identifiers.Network)
	assert.Equal(t, "ssh", sshAlert.Identifiers.Network.Protocol)

	req := &http.Request{
		Method: http.MethodPost,
		Host:   "api.example.com",
		URL:    &url.URL{Path: "/v1/login"},
		Header: http.Header{"User-Agent": []string{"curl/8.0"}},
	}
	httpEv := &utils.StructEvent{
		Pid:         606,
		Request:     req,
		Internal:    true,
		Direction:   consts.Inbound,
		ContainerID: "cid-http",
		Pod:         "pod-http",
	}
	httpFailure := &types.GenericRuleFailure{}
	NewHTTPAdapter().SetFailureMetadata(httpFailure, &events.EnrichedEvent{Event: httpEv}, nil)
	httpAlert := httpFailure.GetBaseRuntimeAlert()
	assert.Equal(t, true, httpAlert.Arguments["internal"])
	assert.Equal(t, consts.Inbound, httpAlert.Arguments["direction"])
	require.NotNil(t, httpAlert.Identifiers.Http)
	assert.Equal(t, http.MethodPost, httpAlert.Identifiers.Http.Method)
	assert.Equal(t, "api.example.com", httpAlert.Identifiers.Http.Domain)
	assert.Equal(t, "/v1/login", httpAlert.Identifiers.Http.Endpoint)
	assert.Equal(t, "curl/8.0", httpAlert.Identifiers.Http.UserAgent)

	ok, opName := GetOpcodeName(uint8(iouringsyscall.IORING_OP_OPENAT))
	assert.True(t, ok)
	assert.Equal(t, "Open file (relative)", opName)

	okUnknown, unknownName := GetOpcodeName(255)
	assert.False(t, okUnknown)
	assert.Equal(t, "Unknown operation", unknownName)

	ioEv := &utils.StructEvent{
		Pid:         707,
		Comm:        "uring-worker",
		Opcode:      int(iouringsyscall.IORING_OP_OPENAT),
		Flags:       []string{"IOSQE_ASYNC"},
		ContainerID: "cid-uring",
		Pod:         "pod-uring",
	}
	ioFailure := &types.GenericRuleFailure{}
	NewIoUringAdapter().SetFailureMetadata(ioFailure, &events.EnrichedEvent{Event: ioEv}, nil)
	ioAlert := ioFailure.GetBaseRuntimeAlert()
	assert.Equal(t, int(iouringsyscall.IORING_OP_OPENAT), ioAlert.Arguments["opcode"])
	assert.Equal(t, "Open file (relative)", ioAlert.Arguments["operation"])
}
