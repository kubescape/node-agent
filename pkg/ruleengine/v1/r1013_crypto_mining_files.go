package ruleengine

import (
	"fmt"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R1013ID   = "R1013"
	R1013Name = "Crypto Mining files access"
)

// CryptoMiningFilesAccessPathsPrefixs is a list because of symlinks.
var CryptoMiningFilesAccessPathsPrefix = []string{
	"/sys/devices/system/cpu/cpu1/cache/index1/shared_cpu_map",
	"/sys/devices/system/cpu/cpu0/cache/index1/level",
	"/sys/devices/system/cpu/cpu0/topology/core_cpus",
	"/sys/devices/system/cpu/cpu1/cache/index0/size",
	"/sys/devices/system/cpu/cpu3/cache/index2/number_of_sets",
	"/sys/devices/system/cpu/cpu0/cache/index2/physical_line_partition",
	"/sys/devices/system/cpu/cpu1/cache/index3/size",
	"/sys/devices/system/node/node0/hugepages",
	"/sys/devices/system/cpu/cpu2/topology/core_id",
	"/sys/devices/system/cpu/cpu0/cache/index2/shared_cpu_map",
	"/dev/null",
	"/proc/1/fd",
	"/sys/devices/system/cpu/cpu3/cache/index3/shared_cpu_map",
	"/sys/devices/virtual/dmi/id/board_name",
	"/sys/devices/system/cpu/cpu0/cache/index0/id",
	"/sys/devices/virtual/dmi/id/chassis_serial",
	"/sys/devices/system/cpu/cpu1/topology/core_cpus",
	"/sys/devices/system/cpu/cpu1/topology/cluster_cpus",
	"/sys/devices/system/cpu/cpu0/cache/index3/physical_line_partition",
	"/sys/devices/system/cpu/cpu1/cache/index1/level",
	"/sys/devices/system/node/node0/cpumap",
	"/sys/devices/system/cpu/cpu2/cache/index3/id",
	"/sys/devices/system/cpu/cpu2/topology/cluster_cpus",
	"/sys/devices/system/cpu/cpu0/cache/index1/id",
	"/sys/devices/virtual/dmi/id/product_serial",
	"/sys/devices/system/cpu/cpu0/cache/index0/number_of_sets",
	"/sys/devices/system/cpu/cpu0/cache/index2/level",
	"/sys/devices/system/cpu/cpu2/cache/index0/level",
	"/sys/devices/system/cpu/cpu0/topology/package_cpus",
	"/sys/devices/system/cpu/cpu2/cache/index0/coherency_line_size",
	"/sys/devices/system/cpu/cpu2/cache/index3/shared_cpu_map",
	"/sys/devices/system/cpu/cpu3/topology/die_cpus",
	"/sys/devices/system/cpu/cpu0/cache/index3/number_of_sets",
	"/sys/devices/system/cpu/cpu1/cache/index0/id",
	"/sys/devices/system/cpu/cpu2/cache/index2/number_of_sets",
	"/sys/kernel/mm/hugepages",
	"/sys/devices/system/cpu/cpu0/cache/index1/shared_cpu_map",
	"/sys/devices/system/cpu/cpu1/cache/index3/level",
	"/sys/devices/system/cpu/cpu0/cache/index3/type",
	"/etc/resolv.conf",
	"/sys/devices/system/cpu/cpu1/cache/index0/coherency_line_size",
	"/sys/devices/system/cpu/cpu3/cache/index0/coherency_line_size",
	"/sys/devices/system/cpu/cpu0/cache/index2/size",
	"/sys/devices/system/cpu/cpu1/cache/index1/id",
	"/sys/devices/virtual/dmi/id/board_vendor",
	"/usr/lib/x86_64-linux-gnu/libc.so.6",
	"/sys/devices/system/cpu/cpu1/topology/package_cpus",
	"/sys/devices/system/cpu/cpu1/cache/index1/type",
	"/sys/fs/cgroup/cpuset.cpus.effective",
	"/sys/devices/system/cpu/cpu1/topology/die_cpus",
	"/sys/devices/system/cpu/cpu1/topology/core_id",
	"/sys/devices/system/cpu/cpu0/cache/index3/level",
	"/sys/devices/system/cpu/cpu2/cache/index3/coherency_line_size",
	"/sys/devices/virtual/dmi/id/product_version",
	"/sys/devices/system/cpu/cpu1/cache/index0/number_of_sets",
	"/sys/devices/system/cpu/cpu3/cache/index3/id",
	"/sys/devices/system/cpu/cpu3/cache/index2/size",
	"/sys/devices/system/cpu/cpu0/topology/cluster_cpus",
	"/sys/devices/system/cpu/cpu0/cache/index2/coherency_line_size",
	"/sys/devices/system/cpu/cpu1/cache/index2/shared_cpu_map",
	"/sys/devices/virtual/dmi/id/bios_vendor",
	"/sys/devices/system/cpu/cpu3/topology/core_cpus",
	"/sys/devices/system/cpu/cpu2/cache/index0/shared_cpu_map",
	"/sys/devices/system/cpu/cpu3/cache/index3/type",
	"/sys/devices/system/cpu/cpu2/topology/package_cpus",
	"/sys/devices/virtual/dmi/id/bios_version",
	"/sys/devices/system/cpu/cpu0/cache/index2/id",
	"/sys/devices/system/cpu/cpu1/cache/index3/id",
	"/sys/devices/system/cpu/cpu3/cache/index3/size",
	"/sys/devices/system/cpu/cpu3/cache/index3/number_of_sets",
	"/sys/devices/system/cpu/cpu3/topology/physical_package_id",
	"/sys/devices/system/cpu/cpu1/cache/index0/shared_cpu_map",
	"/sys/devices/virtual/dmi/id/chassis_type",
	"/sys/devices/virtual/dmi/id/chassis_asset_tag",
	"/sys/devices/system/cpu/cpu0/topology/die_cpus",
	"/sys/devices/system/cpu/cpu3/cache/index1/shared_cpu_map",
	"/sys/devices/system/cpu/cpu3/topology/core_id",
	"/sys/devices/system/cpu/cpu3/cache/index3/level",
	"/sys/devices/system/cpu/cpu0/cache/index0/physical_line_partition",
	"/sys/devices/system/cpu/possible",
	"/sys/devices/system/cpu/cpu2/cache/index2/shared_cpu_map",
	"/sys/devices/virtual/dmi/id/product_name",
	"/sys/devices/system/cpu/cpu0/cache/index2/type",
	"/sys/devices/system/cpu/cpu0/cache/index0/size",
	"/sys/devices/system/cpu/cpu2/cache/index0/number_of_sets",
	"/sys/devices/virtual/dmi/id/board_version",
	"/sys/devices/system/cpu/cpu0/cache/index0/type",
	"/sys/devices/virtual/dmi/id/board_serial",
	"/sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages",
	"/sys/devices/system/cpu/cpu3/cache/index2/type",
	"/sys/devices/system/cpu/cpu1/cache/index3/physical_line_partition",
	"/sys/devices/system/cpu/cpu3/cache/index3/physical_line_partition",
	"/sys/devices/system/cpu/cpu2/cache/index2/coherency_line_size",
	"/sys/devices/system/cpu/cpu2/cache/index2/id",
	"/sys/devices/system/cpu/cpu3/topology/package_cpus",
	"/sys/devices/system/cpu/cpu3/cache/index1/id",
	"/sys/devices/system/cpu/cpu0/cache/index3/size",
	"/sys/devices/system/cpu/cpu1/cache/index2/physical_line_partition",
	"/sys/devices/system/cpu/cpu3/cache/index2/physical_line_partition",
	"/sys/devices/system/cpu/cpu2/cache/index3/level",
	"/sys/devices/system/cpu/cpu1/topology/physical_package_id",
	"/sys/devices/system/cpu/cpu1/cache/index2/number_of_sets",
	"/sys/devices/system/cpu/cpu2/cache/index3/physical_line_partition",
	"/sys/devices/system/cpu/cpu2/cache/index1/type",
	"/sys/devices/system/cpu/cpu3/cache/index0/type",
	"/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages",
	"/sys/devices/system/cpu/cpu3/cache/index0/id",
	"/proc/meminfo",
	"/proc/1/cpuset",
	"/sys/devices/system/cpu/online",
	"/sys/devices/system/cpu/cpu2/topology/physical_package_id",
	"/sys/devices/virtual/dmi/id/chassis_vendor",
	"/sys/devices/system/cpu/cpu0/topology/core_id",
	"/sys/devices/system/cpu/cpu2/cache/index2/physical_line_partition",
	"/sys/devices/system/cpu/cpu1/cache/index3/shared_cpu_map",
	"/etc/ld.so.cache",
	"/sys/devices/system/cpu/cpu3/cache/index0/size",
	"/sys/devices/system/cpu/cpu0/cache/index3/coherency_line_size",
	"/usr/lib/x86_64-linux-gnu/libm.so.6",
	"/sys/devices/system/cpu/cpu3/cache/index1/type",
	"/sys/devices/system/cpu/cpu2/cache/index0/type",
	"/sys/devices/system/cpu/cpu3/cache/index2/coherency_line_size",
	"/sys/devices/system/cpu/cpu1/cache/index2/coherency_line_size",
	"/sys/devices/system/cpu/cpu2/cache/index1/level",
	"/proc/1/mounts",
	"/etc/nsswitch.conf",
	"/sys/devices/system/cpu/cpu0/topology/physical_package_id",
	"/sys/devices/system/cpu/cpu2/topology/die_cpus",
	"/sys/devices/system/cpu/cpu2/cache/index0/size",
	"/sys/devices/system/cpu/cpu2/cache/index2/type",
	"/proc/sys/vm/nr_hugepages",
	"/sys/devices/system/cpu/cpu1/cache/index2/size",
	"/sys/devices/system/cpu/cpu0/cache/index0/shared_cpu_map",
	"/proc/cpuinfo",
	"/sys/devices/system/cpu/cpu3/cache/index2/level",
	"/sys/devices/virtual/dmi/id/chassis_version",
	"/sys/devices/virtual/dmi/id/product_uuid",
	"/sys/devices/system/cpu/cpu1/cache/index0/level",
	"/sys/devices/system/cpu/cpu1/cache/index3/type",
	"/sys/devices/system/cpu/cpu3/cache/index2/shared_cpu_map",
	"/sys/devices/system/cpu/cpu2/cache/index1/shared_cpu_map",
	"/sys/devices/system/cpu/cpu3/cache/index2/id",
	"/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages",
	"/sys/devices/system/cpu/cpu0/cache/index2/number_of_sets",
	"/sys/devices/system/cpu/cpu0/cache/index0/level",
	"/sys/devices/system/cpu/cpu2/cache/index1/id",
	"/sys/devices/system/cpu/cpu2/cache/index3/number_of_sets",
	"/sys/devices/virtual/dmi/id/sys_vendor",
	"/sys/devices/system/cpu/cpu2/cache/index2/level",
	"/sys/devices/system/cpu/cpu3/topology/cluster_cpus",
	"/sys/devices/system/cpu/cpu0/cache/index3/shared_cpu_map",
	"/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages",
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size",
	"/sys/devices/system/cpu/cpu0/cache/index1/type",
	"/sys/devices/system/cpu/cpu0/cache/index3/id",
	"/sys/devices/system/cpu/cpu3/cache/index1/level",
	"/sys/bus/dax/devices",
	"/sys/devices/system/cpu/cpu2/cache/index0/id",
	"/sys/devices/system/cpu/cpu2/cache/index3/size",
	"/sys/devices/system/node/online",
	"/sys/devices/system/cpu/cpu3/cache/index0/number_of_sets",
	"/sys/devices/virtual/dmi/id/board_asset_tag",
	"/sys/devices/system/cpu/cpu2/topology/core_cpus",
	"/etc/hosts",
	"/sys/devices/system/cpu/cpu3/cache/index0/physical_line_partition",
	"/sys/devices/system/cpu/cpu2/cache/index2/size",
	"/sys/devices/system/cpu/cpu3/cache/index0/level",
	"/sys/devices/virtual/dmi/id",
	"/sys/devices/system/cpu/cpu1/cache/index0/physical_line_partition",
	"/sys/devices/system/cpu/cpu1/cache/index3/coherency_line_size",
	"/sys/devices/system/cpu/cpu1/cache/index2/type",
	"/sys/fs/cgroup/cpuset.mems.effective",
	"/etc/host.conf",
	"/sys/devices/system/cpu/cpu3/cache/index3/coherency_line_size",
	"/sys/devices/system/cpu",
	"/sys/fs/cgroup/cgroup.controllers",
	"/sys/devices/system/cpu/cpu1/cache/index2/level",
	"/sys/devices/system/cpu/cpu2/cache/index3/type",
	"/sys/devices/system/cpu/cpu2/cache/index0/physical_line_partition",
	"/sys/devices/system/node/node0/meminfo",
	"/sys/devices/system/cpu/cpu1/cache/index2/id",
	"/sys/devices/system/cpu/cpu3/cache/index0/shared_cpu_map",
	"/sys/devices/system/cpu/cpu1/cache/index0/type",
	"/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
	"/sys/devices/virtual/dmi/id/bios_date",
	"/sys/devices/system/cpu/cpu1/cache/index3/number_of_sets",
	"/sys/devices/system/cpu",
}

var R1013CryptoMiningFilesAccessRuleDescriptor = RuleDescriptor{
	ID:          R1013ID,
	Name:        R1013Name,
	Description: "Detecting Crypto miners communication by files access",
	Tags:        []string{"crypto", "miners", "malicious", "whitelisted"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.OpenEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1013CryptoMiningFilesAccess()
	},
}
var _ ruleengine.RuleEvaluator = (*R1013CryptoMiningFilesAccess)(nil)

type R1013CryptoMiningFilesAccess struct {
	BaseRule
}

func CreateRuleR1013CryptoMiningFilesAccess() *R1013CryptoMiningFilesAccess {
	return &R1013CryptoMiningFilesAccess{}
}
func (rule *R1013CryptoMiningFilesAccess) Name() string {
	return R1013Name
}

func (rule *R1013CryptoMiningFilesAccess) ID() string {
	return R1013ID
}

func (rule *R1013CryptoMiningFilesAccess) DeleteRule() {
}

func (rule *R1013CryptoMiningFilesAccess) generatePatchCommand(event *traceropentype.Event, ap *v1beta1.ApplicationProfile) string {
	flagList := "["
	for _, arg := range event.Flags {
		flagList += "\"" + arg + "\","
	}
	// remove the last comma
	if len(flagList) > 1 {
		flagList = flagList[:len(flagList)-1]
	}
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"opens\": [{\"path\": \"%s\", \"flags\": %s}]}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(),
		event.GetContainer(), event.FullPath, flagList)
}

func (rule *R1013CryptoMiningFilesAccess) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	openEvent, ok := event.(*traceropentype.Event)
	if !ok {
		return nil
	}

	shouldCheckEvent := false
	for _, prefix := range CryptoMiningFilesAccessPathsPrefix {
		if strings.HasPrefix(openEvent.FullPath, prefix) {
			shouldCheckEvent = true
			break
		}
	}

	if !shouldCheckEvent {
		return nil
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    openEvent.Pid,
			FixSuggestions: fmt.Sprintf("If this is a legitimate action, please consider removing this workload from the binding of this rule."),
			Severity:       R1013CryptoMiningFilesAccessRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: openEvent.Comm,
				Gid:  &openEvent.Gid,
				PID:  openEvent.Pid,
				Uid:  &openEvent.Uid,
			},
			ContainerID: openEvent.Runtime.ContainerID,
		},
		TriggerEvent: openEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected access to crypto mining-related file: %s with flags: %s in: %s", openEvent.FullPath, strings.Join(openEvent.Flags, ","), openEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: openEvent.GetPod(),
		},
		RuleID: rule.ID(),
	}

	return &ruleFailure
}

func (rule *R1013CryptoMiningFilesAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1013CryptoMiningFilesAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
