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

// getExecPathWithExePath resolves the exec path symmetrically with the
// recording side's resolveExecPath in
// pkg/containerprofilemanager/v1/event_reporting.go. Precedence:
//
//   1. exepath — kernel-authoritative; the only spoof-resistant source.
//      argv[0] is user-controllable (man 3 exec) even when absolute, so
//      a process can lie about its identity via `exec -a /bin/sh sleep`
//      while /proc/<pid>/exe stays /usr/bin/sleep. Trusting absolute
//      argv[0] would let that lie pass an ap.was_executed check for
//      /bin/sh.
//
//   2. argv[0] when non-empty AND exepath empty (fexecve / execveat
//      AT_EMPTY_PATH — the libpam helper invocation pattern; defers to
//      the 2-arg fallback below).
//
//   3. comm as final fallback (also via 2-arg).
//
// This closes the fork-shell mismatch — `sh -c …` records /bin/sh on
// the recording side and the rule side now queries /bin/sh too — while
// preserving the kernel-authoritative argv[0]-spoofing protection that
// the prior absolute-argv[0]-wins tier had eroded.
func (l *parseLibrary) getExecPathWithExePath(args ref.Val, comm ref.Val, exepath ref.Val) ref.Val {
	exepathStr, ok := exepath.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(exepath)
	}

	if exepathStr != "" {
		return types.String(exepathStr)
	}

	// exepath empty (fexecve / AT_EMPTY_PATH) — fall back to argv[0],
	// then comm, via the 2-arg path.
	return l.getExecPath(args, comm)
}
