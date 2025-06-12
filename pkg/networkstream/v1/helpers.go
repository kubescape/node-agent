package networkstream

import "strings"

type WorkloadKind string

const (
	Deployment  WorkloadKind = "Deployment"
	StatefulSet WorkloadKind = "StatefulSet"
	DaemonSet   WorkloadKind = "DaemonSet"
	CronJob     WorkloadKind = "CronJob"
	ReplicaSet  WorkloadKind = "ReplicaSet"
)

func extractWorkloadName(podName string, kind WorkloadKind) string {
	if podName == "" {
		return ""
	}

	parts := strings.Split(podName, "-")
	if len(parts) == 1 {
		return podName
	}

	switch kind {
	case Deployment:
		// Remove last two parts (hash and random string)
		// e.g., nginx-7869c5f687-xy123 -> nginx
		if len(parts) >= 3 {
			return strings.Join(parts[:len(parts)-2], "-")
		}

	case StatefulSet:
		// Remove the last part (ordinal number)
		// e.g., mysql-0 -> mysql
		return strings.Join(parts[:len(parts)-1], "-")

	case DaemonSet:
		// Remove the last part (random string)
		// e.g., fluentd-78k9x -> fluentd
		return strings.Join(parts[:len(parts)-1], "-")

	case CronJob:
		// Remove last two parts (job hash and random string)
		// e.g., backup-cron-1234567890-abcde -> backup-cron
		if len(parts) >= 3 {
			return strings.Join(parts[:len(parts)-2], "-")
		}
	}

	return podName
}
