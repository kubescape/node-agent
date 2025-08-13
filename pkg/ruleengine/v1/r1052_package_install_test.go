package ruleengine

import (
	"strings"
	"testing"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1052PackageInstallDetected(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1052PackageInstallDetected()

	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Test basic rule properties
	if r.Name() != R1052Name {
		t.Errorf("Expected rule name to be %s, got %s", R1052Name, r.Name())
	}

	if r.ID() != R1052ID {
		t.Errorf("Expected rule ID to be %s, got %s", R1052ID, r.ID())
	}

	// Test non-exec event type (should return nil)
	nonExecEvent := &events.ExecEvent{}
	ruleResult := r.ProcessEvent(utils.NetworkEventType, nonExecEvent, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil for non-exec event type")
	}

	// Test non-package install commands (should return nil)
	testCases := []struct {
		name string
		comm string
		args []string
	}{
		{"ls command", "ls", []string{"-la"}},
		{"cat command", "cat", []string{"/etc/passwd"}},
		{"echo command", "echo", []string{"hello"}},
		{"curl command", "curl", []string{"https://example.com"}},
		{"wget command", "wget", []string{"https://example.com"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := &events.ExecEvent{
				Event: tracerexectype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test",
								},
							},
						},
					},
					Comm: tc.comm,
					Args: tc.args,
				},
			}

			ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
			if ruleResult != nil {
				t.Errorf("Expected ruleResult to be nil for %s command", tc.comm)
			}
		})
	}

	// Test package install commands (should return rule failure)
	installTestCases := []struct {
		name string
		comm string
		args []string
	}{
		{"apt install", "apt", []string{"install", "nginx"}},
		{"apt add", "apt", []string{"add", "curl"}},
		{"apk add", "apk", []string{"add", "git"}},
		{"yum install", "yum", []string{"install", "httpd"}},
		{"dnf install", "dnf", []string{"install", "python3"}},
		{"zypper install", "zypper", []string{"install", "vim"}},
		{"pacman -S", "pacman", []string{"-S", "firefox"}},
		{"brew install", "brew", []string{"install", "node"}},
		{"snap install", "snap", []string{"install", "code"}},
		{"flatpak install", "flatpak", []string{"install", "gimp"}},
	}

	for _, tc := range installTestCases {
		t.Run(tc.name, func(t *testing.T) {
			e := &events.ExecEvent{
				Event: tracerexectype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test",
								},
							},
						},
					},
					Comm: tc.comm,
					Args: tc.args,
					Pid:  12345,
					Ppid: 1234,
					Uid:  1000,
					Gid:  1000,
					Cwd:  "/tmp",
				},
			}

			ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
			if ruleResult == nil {
				t.Errorf("Expected ruleResult for %s command with args %v", tc.comm, tc.args)
			}

			// Verify the rule failure details
			if ruleResult != nil {
				genericFailure, ok := ruleResult.(*GenericRuleFailure)
				if !ok {
					t.Errorf("Expected GenericRuleFailure, got %T", ruleResult)
					return
				}

				if genericFailure.BaseRuntimeAlert.AlertName != R1052Name {
					t.Errorf("Expected alert name %s, got %s", R1052Name, genericFailure.BaseRuntimeAlert.AlertName)
				}

				if genericFailure.RuleID != R1052ID {
					t.Errorf("Expected rule ID %s, got %s", R1052ID, genericFailure.RuleID)
				}

				if genericFailure.BaseRuntimeAlert.InfectedPID != 12345 {
					t.Errorf("Expected PID 12345, got %d", genericFailure.BaseRuntimeAlert.InfectedPID)
				}

				// Check arguments
				if cmd, ok := genericFailure.BaseRuntimeAlert.Arguments["command"]; !ok || cmd != tc.comm {
					t.Errorf("Expected command argument %s, got %v", tc.comm, cmd)
				}

				expectedArgs := strings.Join(tc.args, " ")
				if args, ok := genericFailure.BaseRuntimeAlert.Arguments["args"]; !ok || args != expectedArgs {
					t.Errorf("Expected args argument %s, got %v", expectedArgs, args)
				}
			}
		})
	}

	// Test case-insensitive matching
	t.Run("case insensitive matching", func(t *testing.T) {
		e := &events.ExecEvent{
			Event: tracerexectype.Event{
				Event: eventtypes.Event{
					CommonData: eventtypes.CommonData{
						K8s: eventtypes.K8sMetadata{
							BasicK8sMetadata: eventtypes.BasicK8sMetadata{
								ContainerName: "test",
							},
						},
					},
				},
				Comm: "APT",
				Args: []string{"INSTALL", "nginx"},
			},
		}

		ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
		if ruleResult == nil {
			t.Errorf("Expected ruleResult for case-insensitive APT INSTALL command")
		}
	})

	// Test partial argument matching
	t.Run("partial argument matching", func(t *testing.T) {
		e := &events.ExecEvent{
			Event: tracerexectype.Event{
				Event: eventtypes.Event{
					CommonData: eventtypes.CommonData{
						K8s: eventtypes.K8sMetadata{
							BasicK8sMetadata: eventtypes.BasicK8sMetadata{
								ContainerName: "test",
							},
						},
					},
				},
				Comm: "apt",
				Args: []string{"update", "&&", "apt", "install", "nginx"},
			},
		}

		ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
		if ruleResult == nil {
			t.Errorf("Expected ruleResult for apt command with install in args")
		}
	})

	// Test non-install package manager commands (should return nil)
	nonInstallTestCases := []struct {
		name string
		comm string
		args []string
	}{
		{"apt update", "apt", []string{"update"}},
		{"apt upgrade", "apt", []string{"upgrade"}},
		{"apt remove", "apt", []string{"remove", "nginx"}},
		{"apk update", "apk", []string{"update"}},
		{"yum update", "yum", []string{"update"}},
		{"dnf update", "dnf", []string{"update"}},
		{"pacman -U", "pacman", []string{"-U", "package.tar.xz"}},
		{"brew update", "brew", []string{"update"}},
		{"snap refresh", "snap", []string{"refresh"}},
	}

	for _, tc := range nonInstallTestCases {
		t.Run(tc.name, func(t *testing.T) {
			e := &events.ExecEvent{
				Event: tracerexectype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test",
								},
							},
						},
					},
					Comm: tc.comm,
					Args: tc.args,
					Pid:  12345,
					Ppid: 1234,
					Uid:  1000,
					Gid:  1000,
					Cwd:  "/tmp",
				},
			}

			ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
			if ruleResult != nil {
				t.Errorf("Expected ruleResult to be nil for %s command with args %v", tc.comm, tc.args)
			}
		})
	}
}
