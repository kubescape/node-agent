package setters

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/rulefailurecreator"
	"github.com/kubescape/node-agent/pkg/utils"
)

// RegisterAllSetters registers all event type setters with the rule failure creator
func RegisterAllSetters(creator rulefailurecreator.RuleFailureCreatorInterface) {
	// Register all event type setters
	creator.RegisterCreator(utils.ExecveEventType, NewExecCreator())
	creator.RegisterCreator(utils.OpenEventType, NewOpenCreator())
	creator.RegisterCreator(utils.CapabilitiesEventType, NewCapabilitiesCreator())
	creator.RegisterCreator(utils.DnsEventType, NewDnsCreator())
	creator.RegisterCreator(utils.NetworkEventType, NewNetworkCreator())
	creator.RegisterCreator(utils.SyscallEventType, NewSyscallCreator())
	creator.RegisterCreator(utils.SymlinkEventType, NewSymlinkCreator())
	creator.RegisterCreator(utils.HardlinkEventType, NewHardlinkCreator())
	creator.RegisterCreator(utils.SSHEventType, NewSSHCreator())
	creator.RegisterCreator(utils.HTTPEventType, NewHTTPCreator())
	creator.RegisterCreator(utils.PtraceEventType, NewPtraceCreator())
	creator.RegisterCreator(utils.IoUringEventType, NewIoUringCreator())
	creator.RegisterCreator(utils.ForkEventType, NewForkCreator())
	creator.RegisterCreator(utils.ExitEventType, NewExitCreator())
	creator.RegisterCreator(utils.RandomXEventType, NewRandomXCreator())
}
