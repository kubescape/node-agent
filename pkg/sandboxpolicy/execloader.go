package sandboxpolicy

import (
	"path"
	"strings"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// loaderNames are file names of real loaders. They serve only to recognise an
// authored allow that names a loader on purpose (LoaderAllowRule); they are not
// the list of denied loaders, which is the full compiler's glob. A loader
// missing here (ld-linux.so.2, ld-linux-armhf.so.3) fails closed: an allow of
// it does not turn the loader deny off. V1 targets amd64 only.
var loaderNames = []string{"ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1", "ld-musl-x86_64.so.1", "ld-musl-aarch64.so.1", "ld-2.31.so"}

// ExecDeniesByPath reports whether an exec section denies by path: a deny
// default, or a deny rule with paths. The full compiler then adds a deny rule
// for the dynamic loaders, unless LoaderAllowRule finds an allow of one.
func ExecDeniesByPath(exec api.ExecSection) bool {
	if exec.Default == api.ActionDeny {
		return true
	}
	for _, r := range exec.Rules {
		if r.Action == api.ActionDeny && len(r.Target.Path) != 0 {
			return true
		}
	}
	return false
}

// LoaderAllowRule returns the first allow rule of an exec section that names
// a dynamic loader on purpose, and the path that names it. Such a rule keeps
// the loaders runnable for the whole policy, for every actor: the full
// compiler adds no loader deny, and the status reports the rule
// (ExecLoaderAllowed). The section is the compiled one (path classes expanded,
// ContainerProfile rules included), as the full compiler sees it.
//
// A path names a loader when its file name (the part after the last "/")
// starts with a literal "ld-" and matches a name in loaderNames: "ld-musl-*",
// "ld-linux-*" and "ld-2.31.so" count, but a library glob such as "*.so*" does
// not, although it matches a loader's file name. The directory is ignored, so
// an app that ships its own loader (/opt/app/ld-linux-x86-64.so.2) also keeps
// the image's loaders runnable.
func LoaderAllowRule(exec api.ExecSection) (rule api.ExecRule, loaderPath string, ok bool) {
	for _, r := range exec.Rules {
		if r.Action != api.ActionAllow {
			continue
		}
		for _, p := range r.Target.Path {
			name := p[strings.LastIndex(p, "/")+1:]
			if !strings.HasPrefix(name, "ld-") {
				continue
			}
			for _, loader := range loaderNames {
				if matched, _ := path.Match(name, loader); matched {
					return r, p, true
				}
			}
		}
	}
	return api.ExecRule{}, "", false
}
