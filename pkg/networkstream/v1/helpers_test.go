package networkstream

import "testing"

func Test_extractWorkloadName(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		kind    WorkloadKind
		want    string
	}{
		{name: "daemonset with multiple hyphens in name", podName: "endpoint-traffic-daemonset-6wbgz", kind: DaemonSet, want: "endpoint-traffic-daemonset"},
		{name: "deployment basic case", podName: "nginx-7869c5f687-xy123", kind: Deployment, want: "nginx"},
		{name: "deployment with multiple hyphens in name", podName: "web-app-backend-76d5f68594-xyz89", kind: Deployment, want: "web-app-backend"},
		{name: "deployment with less than 3 parts", podName: "nginx-simple", kind: Deployment, want: "nginx-simple"},
		{name: "statefulset basic case", podName: "mysql-0", kind: StatefulSet, want: "mysql"},
		{name: "statefulset with multiple hyphens in name", podName: "mongodb-cluster-2", kind: StatefulSet, want: "mongodb-cluster"},
		{name: "statefulset with larger ordinal", podName: "postgres-master-15", kind: StatefulSet, want: "postgres-master"},
		{name: "daemonset basic case", podName: "fluentd-78k9x", kind: DaemonSet, want: "fluentd"},
		{name: "daemonset with multiple hyphens in name", podName: "calico-node-ab12c", kind: DaemonSet, want: "calico-node"},
		{name: "empty pod name", podName: "", kind: Deployment, want: ""},
		{name: "pod name without hyphens", podName: "simplepod", kind: Deployment, want: "simplepod"},
		{name: "pod name with only hyphens", podName: "-", kind: Deployment, want: "-"},
		{name: "deployment with special characters", podName: "app.web-76d5f68594-xyz89", kind: Deployment, want: "app.web"},
		{name: "deployment ending in hyphen", podName: "webserver-76d5f68594-", kind: Deployment, want: "webserver"},
		{name: "statefulset ending in hyphen", podName: "database-", kind: StatefulSet, want: "database"},
		{name: "daemonset ending in hyphen", podName: "logger-", kind: DaemonSet, want: "logger"},

		// CronJob test cases
		{name: "cronjob basic case", podName: "backup-1234567890-abcde", kind: CronJob, want: "backup"},
		{name: "cronjob with multiple hyphens in name", podName: "nightly-data-backup-1587930600-xyzab", kind: CronJob, want: "nightly-data-backup"},
		{name: "cronjob with complex name", podName: "app.db-backup-1587930600-87654", kind: CronJob, want: "app.db-backup"},
		{name: "cronjob with less than 3 parts", podName: "simple-backup", kind: CronJob, want: "simple-backup"},
		{name: "cronjob ending in hyphen", podName: "backup-job-1587930600-", kind: CronJob, want: "backup-job"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractWorkloadName(tt.podName, tt.kind)
			if got != tt.want {
				t.Errorf("extractWorkloadName() = %v, want %v", got, tt.want)
			}
		})
	}
}
