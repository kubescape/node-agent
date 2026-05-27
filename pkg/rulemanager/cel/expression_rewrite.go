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

// rewriteDeprecatedHelpers upgrades known-deprecated helper call sites in a
// CEL expression to their safer current form. Returns the rewritten
// expression plus operator-visible notices describing each rewrite or
// remaining concern.
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
func rewriteDeprecatedHelpers(expression string) (string, []string) {
	var notices []string

	if twoArgEventGetExecPath.MatchString(expression) {
		original := expression
		expression = twoArgEventGetExecPath.ReplaceAllString(expression,
			"parse.get_exec_path(event.args, event.comm, event.exepath)")
		notices = append(notices, fmt.Sprintf(
			"auto-rewrote 2-arg parse.get_exec_path → 3-arg with event.exepath fallback; the 2-arg form trusts argv[0] which is user-controllable and bypassable via `exec -a <allowed-path> <real-binary>`. Update RuleBindings to call the 3-arg form explicitly. Original expression: %q",
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
