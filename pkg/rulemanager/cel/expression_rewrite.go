package cel

import (
	"fmt"
	"regexp"
)

// twoArgEventGetExecPath matches the canonical 2-arg call against the event
// variable — safely auto-upgradable to 3-arg by passing event.exepath as the
// kernel-authoritative resolution source.
var twoArgEventGetExecPath = regexp.MustCompile(`\bparse\.get_exec_path\(\s*event\.args\s*,\s*event\.comm\s*\)`)

// anyTwoArgGetExecPath matches any 2-arg call site. After the canonical
// rewrite has run, anything still matching is non-canonical (caller used
// identifiers other than event.args / event.comm, or literal values) and
// cannot be safely upgraded without operator intent. The pattern
// `[^,)]+` halts at the first comma, so a 3-arg call does not match.
var anyTwoArgGetExecPath = regexp.MustCompile(`\bparse\.get_exec_path\([^,)]+,\s*[^,)]+\)`)

// rewriteDeprecatedHelpers is a compatibility shim that auto-upgrades
// deprecated 2-arg parse.get_exec_path calls to the safer 3-arg form.
// Returns the rewritten expression plus operator-visible notices
// describing each rewrite or remaining concern.
//
// Today this handles ONE rewrite: the 2-arg parse.get_exec_path against
// the event variable. The 2-arg overload returns argv[0] (or comm) which
// is user-controllable — `exec -a /bin/sh sleep 2` yields cmdline=/bin/sh
// while /proc/<pid>/exe is /usr/bin/sleep, so any ap.was_executed-style
// lookup against the 2-arg result is bypassable. The 3-arg form anchors
// on event.exepath (kernel-authoritative) and falls back to argv[0]/comm
// only for fexecve / AT_EMPTY_PATH cases.
//
// Auto-rewriting is intentionally limited to expressions that name the
// event variable explicitly — those are guaranteed to be evaluated against
// an exec event that carries event.exepath, so the rewrite is contract-
// preserving. Non-canonical 2-arg calls (custom identifiers or literals)
// cannot be auto-upgraded; they surface a notice so operators can migrate
// manually.
//
// IMPLEMENTATION NOTE: this is intentionally a text-level regex rewrite,
// not an AST transform. The theoretical risk of mutating a string
// literal that happens to contain the exact 2-arg call pattern (e.g.
// `event.message == "parse.get_exec_path(event.args, event.comm)"`) is
// accepted as negligible: CEL security-rule expressions do not embed
// the helper's call form as a literal, and the alternative (CEL parser
// dependency at this layer + AST walker + serializer) is disproportionate
// to the risk. If a future need surfaces a real-world false-rewrite,
// upgrade to AST-based transformation then.
//
// DEPRECATION NOTICE: the 2-arg parse.get_exec_path overload is
// deprecated. This shim auto-upgrades calls at registration time so
// operators who upgrade the node-agent binary without updating their
// RuleBindings retain the kernel-authoritative behaviour. The shim and
// the 2-arg overload itself will be removed in a future major version;
// migrate RuleBindings to call the 3-arg form explicitly to avoid the
// removal cliff.
func rewriteDeprecatedHelpers(expression string) (string, []string) {
	var notices []string

	if twoArgEventGetExecPath.MatchString(expression) {
		original := expression
		expression = twoArgEventGetExecPath.ReplaceAllString(expression,
			"parse.get_exec_path(event.args, event.comm, event.exepath)")
		notices = append(notices, fmt.Sprintf(
			"[DEPRECATED, to be removed in a future major release] auto-rewrote 2-arg parse.get_exec_path → 3-arg with event.exepath fallback; the 2-arg form trusts argv[0] which is user-controllable and bypassable via `exec -a <allowed-path> <real-binary>`. Update RuleBindings to call the 3-arg form explicitly. Original expression: %q",
			original))
	}

	// After auto-rewrite the canonical pattern is gone. Anything still
	// matching the 2-arg shape is non-canonical — flag it for operator
	// attention but do not modify.
	for _, m := range anyTwoArgGetExecPath.FindAllString(expression, -1) {
		notices = append(notices, fmt.Sprintf(
			"2-arg parse.get_exec_path with non-event arguments cannot be auto-upgraded and remains argv[0]-spoofable: %s",
			m))
	}

	return expression, notices
}
