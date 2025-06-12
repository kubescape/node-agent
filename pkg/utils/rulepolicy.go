package utils

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func MergePolicies(primary, secondary v1beta1.RulePolicy) v1beta1.RulePolicy {
	mergedPolicy := v1beta1.RulePolicy{
		AllowedContainer: primary.AllowedContainer || secondary.AllowedContainer,
	}

	processes := mapset.NewSet[string]()

	for _, process := range primary.AllowedProcesses {
		processes.Add(process)
	}
	for _, process := range secondary.AllowedProcesses {
		processes.Add(process)
	}

	for process := range processes.Iter() {
		mergedPolicy.AllowedProcesses = append(mergedPolicy.AllowedProcesses, process)
	}

	return mergedPolicy
}
