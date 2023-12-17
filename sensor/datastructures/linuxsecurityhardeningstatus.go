package datastructures

type LinuxSecurityHardeningStatus struct {
	AppArmor string `json:"appArmor"`
	SeLinux  string `json:"seLinux"`
}
