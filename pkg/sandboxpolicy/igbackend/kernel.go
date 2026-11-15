package igbackend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// Kernel identifies a running kernel: its release (uname -r), its
// architecture (uname -m) and the SHA-256 of its BTF (/sys/kernel/btf/vmlinux).
// The BTF digest tells two builds with the same release apart.
type Kernel struct {
	Release, Arch, BTF string
}

func (k Kernel) String() string { return k.Release + "," + k.Arch + "," + k.BTF }

// QualifiedKernels lists, per slot section, the kernels on which that
// section's kernel tests passed with the run logs posted on the PRs (AL2023
// amd64 fleet kernels). Each entry names its evidence. Add a kernel only with
// posted evidence; a section with no entry stays NotReady on every kernel.
var QualifiedKernels = map[string][]Kernel{
	// Qualification report 2026-11-11-full-b5a68891-two-kernels.md.
	sandboxpolicy.SectionPrivilege: {
		{Release: "6.12.113-138.209.amzn2023.x86_64", Arch: "x86_64", BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82"},
		{Release: "6.18.56-125.164.amzn2023.x86_64", Arch: "x86_64", BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee"},
	},
	// Qualification report 2026-11-11-full-b5a68891-two-kernels.md.
	sandboxpolicy.SectionFile: {
		{Release: "6.12.113-138.209.amzn2023.x86_64", Arch: "x86_64", BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82"},
	},
	// The network run must pass at the current head (outside-scope deny,
	// missing publication, publish under traffic, coexistence) first.
	sandboxpolicy.SectionNetwork: nil,
}

// AnyKernel in a qualified list admits every kernel (test clusters). The
// gate is then off: policies can be Ready, with the reason KernelGateDisabled.
const AnyKernel = "*"

// ParseQualifiedKernels parses configured entries "release,arch,btf-sha256"
// or AnyKernel, which apply to every section. Empty (nil kernels, any false)
// uses QualifiedKernels.
func ParseQualifiedKernels(entries []string) (kernels []Kernel, any bool, err error) {
	for _, e := range entries {
		if strings.TrimSpace(e) == AnyKernel {
			any = true
			continue
		}
		parts := strings.Split(e, ",")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || len(parts[2]) != sha256.Size*2 {
			return nil, false, fmt.Errorf("qualified kernel %q: want release,arch,btf-sha256 or %q", e, AnyKernel)
		}
		if _, err := hex.DecodeString(parts[2]); err != nil {
			return nil, false, fmt.Errorf("qualified kernel %q: BTF digest: %w", e, err)
		}
		kernels = append(kernels, Kernel{Release: parts[0], Arch: parts[1], BTF: strings.ToLower(parts[2])})
	}
	return kernels, any, nil
}

// KernelGateDisabled is the Ready reason of a section policy on a kernel that
// is admitted only by AnyKernel.
const KernelGateDisabled = "KernelGateDisabled"

// CheckQualifiedKernel returns an EnforcementUnavailableError with reason
// <Section>KernelUnqualified unless k matches a qualified kernel in release,
// architecture and BTF digest. The section still enforces on such a kernel,
// but never reports Ready. With any set, an unlisted kernel is admitted and
// note is the KernelGateDisabled message.
func CheckQualifiedKernel(section string, k Kernel, qualified []Kernel, any bool) (note string, err error) {
	for _, q := range qualified {
		if q == k {
			return "", nil
		}
	}
	if any {
		return fmt.Sprintf("kernel gate disabled (%q): kernel %s is not qualified", AnyKernel, k), nil
	}
	return "", &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: strings.ToUpper(section[:1]) + section[1:] + "KernelUnqualified", Enforcing: true,
		Detail: fmt.Sprintf("kernel %s is not in the qualified list %v", k, qualified)}
}

// RunningKernel reads the running kernel's release, architecture and BTF
// digest (btfPath: /sys/kernel/btf/vmlinux on the host).
func RunningKernel(btfPath string) (Kernel, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Kernel{}, err
	}
	k := Kernel{Release: unix.ByteSliceToString(u.Release[:]), Arch: unix.ByteSliceToString(u.Machine[:])}
	if k.Arch == "" {
		k.Arch = runtime.GOARCH
	}
	f, err := os.Open(btfPath)
	if err != nil {
		return k, fmt.Errorf("kernel BTF: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return k, fmt.Errorf("kernel BTF: %w", err)
	}
	k.BTF = hex.EncodeToString(h.Sum(nil))
	return k, nil
}
