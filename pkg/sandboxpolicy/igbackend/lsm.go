package igbackend

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// CheckBPFLSM returns an EnforcementUnavailableError unless "bpf" is in the
// host's active LSM list. Without it, BPF LSM programs attach but never run
// (for example the default AKS Ubuntu and Azure Linux images), so enforcement
// would be reported while nothing is enforced.
func CheckBPFLSM(hostRoot string) error { return checkBPFLSM(hostRoot, sandboxpolicy.SectionPrivilege) }

func checkBPFLSM(hostRoot, section string) error {
	path := filepath.Join(hostRoot, "sys/kernel/security/lsm")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: "BPFLSMInactive", Detail: fmt.Sprintf("%s is missing (securityfs not mounted)", path)}
	}
	if err != nil {
		return &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: "BPFLSMInactive", Detail: fmt.Sprintf("reading %s: %v", path, err)}
	}
	for _, lsm := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if lsm == "bpf" {
			return nil
		}
	}
	return &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: "BPFLSMInactive",
		Detail: fmt.Sprintf("BPF LSM is not active (active LSMs: %s); add bpf to the lsm= kernel parameter", strings.TrimSpace(string(data)))}
}
