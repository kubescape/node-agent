package seccomp

import (
	"path"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	corev1 "k8s.io/api/core/v1"
)

// FallbackDir is the kubelet seccomp subdirectory for profiles written when the
// runtime cannot take an injected profile. A pod opts in by referencing one.
const FallbackDir = "kubescape-sandbox"

// defaultCapabilities is the CRI default capability set of containerd and CRI-O.
var defaultCapabilities = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID",
	"CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
}

// RuntimeProfile is the seccomp profile kind of a container.
type RuntimeProfile string

const (
	RuntimeProfileUnknown        RuntimeProfile = ""
	RuntimeProfileUnconfined     RuntimeProfile = "Unconfined"
	RuntimeProfileRuntimeDefault RuntimeProfile = "RuntimeDefault"
	RuntimeProfileLocalhost      RuntimeProfile = "Localhost"
)

// RuntimeInfo is what the runtime reported about a container's seccomp profile
// before any adjustment. Policy is the exact profile the runtime would apply.
type RuntimeInfo struct {
	Known  bool
	Kind   RuntimeProfile
	Policy *specs.LinuxSeccomp
}

// Container is what Build needs to know about one container of a pod.
type Container struct {
	Kind         string // regular, init or ephemeral
	Base         Base
	Capabilities []string
	// Default is the runtime's own base profile, when it reported one.
	Default *specs.LinuxSeccomp
	// Assumed is true when the base comes from neither the runtime nor the pod
	// spec: the kubelet may apply RuntimeDefault to pods that set nothing.
	Assumed bool
	// Skip is set when SandboxPolicy must not replace this container's profile.
	Skip string
}

// FallbackFile is the Localhost profile path, relative to the kubelet seccomp
// directory, of a fallback profile. The base is part of the name, so a pod that
// opts in keeps the base its profile was built on.
func FallbackFile(base Base, revision string) string {
	prefix := "uc-"
	if base == BaseRuntimeDefault {
		prefix = "rd-"
	}
	return path.Join(FallbackDir, prefix+revision+".json")
}

func fallbackBase(localhostProfile string) (Base, bool) {
	name := strings.TrimPrefix(localhostProfile, FallbackDir+"/")
	if name == localhostProfile || strings.Contains(name, "/") {
		return 0, false
	}
	switch {
	case strings.HasPrefix(name, "rd-"):
		return BaseRuntimeDefault, true
	case strings.HasPrefix(name, "uc-"):
		return BaseUnconfined, true
	}
	return 0, false
}

// ResolveContainer reads the container's kind, seccomp base and capabilities.
// The runtime's report wins over the pod spec. Without a report, a pod that sets
// no profile is assumed to run RuntimeDefault, the stricter of the two.
func ResolveContainer(pod *corev1.Pod, name string, info RuntimeInfo) (Container, bool) {
	spec, kind, ok := findContainer(pod, name)
	if !ok {
		return Container{}, false
	}
	result := Container{Kind: kind, Capabilities: capabilities(spec.SecurityContext)}
	if sc := spec.SecurityContext; sc != nil && sc.Privileged != nil && *sc.Privileged {
		result.Skip = "privileged container"
		return result, true
	}
	var profile *corev1.SeccompProfile
	if pod.Spec.SecurityContext != nil {
		profile = pod.Spec.SecurityContext.SeccompProfile
	}
	if spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil {
		profile = spec.SecurityContext.SeccompProfile
	}
	if profile != nil && profile.Type == corev1.SeccompProfileTypeLocalhost && profile.LocalhostProfile != nil {
		if base, own := fallbackBase(*profile.LocalhostProfile); own {
			// our own fallback file: rebuild on the base it was built on
			result.Base = base
			return result, true
		}
	}
	if info.Known {
		switch info.Kind {
		case RuntimeProfileLocalhost:
			result.Skip = "container uses its own Localhost seccomp profile"
		case RuntimeProfileUnconfined:
			result.Base = BaseUnconfined
		default:
			result.Base, result.Default = BaseRuntimeDefault, info.Policy
		}
		return result, true
	}
	switch {
	case profile == nil:
		result.Base, result.Assumed = BaseRuntimeDefault, true
	case profile.Type == corev1.SeccompProfileTypeRuntimeDefault:
		result.Base = BaseRuntimeDefault
	case profile.Type == corev1.SeccompProfileTypeLocalhost:
		result.Skip = "container uses its own Localhost seccomp profile"
	default:
		result.Base = BaseUnconfined
	}
	return result, true
}

func findContainer(pod *corev1.Pod, name string) (corev1.Container, string, bool) {
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			return c, "regular", true
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == name {
			return c, "init", true
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if c.Name == name {
			return corev1.Container(c.EphemeralContainerCommon), "ephemeral", true
		}
	}
	return corev1.Container{}, "", false
}

// capabilities applies the container's add and drop lists to the runtime default
// set, the way the CRI runtimes do.
func capabilities(sc *corev1.SecurityContext) []string {
	caps := make(map[string]bool)
	for _, c := range defaultCapabilities {
		caps[c] = true
	}
	if sc != nil && sc.Capabilities != nil {
		for _, c := range sc.Capabilities.Drop {
			if strings.EqualFold(string(c), "ALL") {
				caps = map[string]bool{}
				continue
			}
			delete(caps, capName(c))
		}
		for _, c := range sc.Capabilities.Add {
			if strings.EqualFold(string(c), "ALL") {
				// only these change the runtime default profile
				for _, gated := range []string{"CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_CHROOT", "CAP_DAC_READ_SEARCH", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_RAWIO", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_SYS_NICE", "CAP_SYSLOG", "CAP_BPF", "CAP_PERFMON"} {
					caps[gated] = true
				}
				continue
			}
			caps[capName(c)] = true
		}
	}
	out := make([]string, 0, len(caps))
	for c := range caps {
		out = append(out, c)
	}
	return sortedUnique(out)
}

func capName(c corev1.Capability) string {
	name := strings.ToUpper(string(c))
	if !strings.HasPrefix(name, "CAP_") {
		name = "CAP_" + name
	}
	return name
}
