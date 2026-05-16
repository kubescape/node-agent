package parse

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
)

func (l *parseLibrary) getExecPath(args ref.Val, comm ref.Val) ref.Val {
	argsList, err := celparse.ParseList[string](args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}

	commStr, ok := comm.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(comm)
	}

	// 2-arg overload — back-compat. Resolves args[0] → comm.
	// Callers that have event.exepath SHOULD use the 3-arg overload below
	// to stay symmetric with the recording side's resolveExecPath in
	// pkg/containerprofilemanager/v1/event_reporting.go.
	if len(argsList) > 0 {
		if argsList[0] != "" {
			return types.String(argsList[0])
		}
	}
	return types.String(commStr)
}

// getExecPathWithExePath is the 3-arg overload that resolves the exec
// path with symlink-faithful precedence:
//
//   1. argv[0] when it's an absolute path (`/...`) — preserves symlink
//      identity as invoked (e.g. busybox-based images where /bin/sh,
//      /usr/bin/nslookup, /bin/echo are all symlinks to /bin/busybox;
//      argv[0] carries the symlink form, exepath carries the kernel-
//      resolved target). User-authored profiles list the symlink form,
//      and the recording side (resolveExecPath in
//      pkg/containerprofilemanager/v1/event_reporting.go) uses the same
//      precedence so profile.Path matches what rules query.
//
//   2. exepath when argv[0] is bare (e.g. "sh", "curl") or empty — the
//      kernel-authoritative path is the right tiebreaker here, and
//      preserves the existing argv[0]-spoofing protection: an attacker
//      passing a misleading bare argv[0] (e.g. argv[0]="sshd" while
//      actually exec'ing /usr/bin/curl) gets resolved to the real
//      exepath, not the bare lie. The "absolute path → trust argv[0]"
//      rule is safe because the kernel only exposes an absolute argv[0]
//      when execve was called with that exact path (modulo symlinks
//      that the kernel itself follows transparently).
//
//   3. argv[0] when bare AND exepath empty (fexecve / AT_EMPTY_PATH).
//
//   4. comm as final fallback.
//
// This closes the spurious-R0001 gap on busybox-based containers AND
// the prior fork-shell case where event.exepath was the only source.
func (l *parseLibrary) getExecPathWithExePath(args ref.Val, comm ref.Val, exepath ref.Val) ref.Val {
	exepathStr, ok := exepath.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(exepath)
	}

	argsList, err := celparse.ParseList[string](args)
	if err == nil && len(argsList) > 0 {
		argv0 := argsList[0]
		// Tier 1: absolute argv[0] wins. Symlink-faithful.
		if len(argv0) > 0 && argv0[0] == '/' {
			return types.String(argv0)
		}
	}

	// Tier 2: kernel-authoritative exepath when argv[0] is bare/empty.
	if exepathStr != "" {
		return types.String(exepathStr)
	}

	// Tiers 3+4: defer to 2-arg fallback (argv[0]-bare → comm).
	return l.getExecPath(args, comm)
}
