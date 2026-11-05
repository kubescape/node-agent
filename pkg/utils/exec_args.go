package utils

import (
	"strings"

	igconsts "github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_exec/consts"
)

// The exec datasource has no array type, so argv travels as one string whose
// arguments are separated by igconsts.ArgsSeparator (U+00A0). A process
// controls its own argv, so an argument may itself contain U+00A0. To keep the
// argument boundaries, each argument is escaped before the join: a backslash
// becomes two backslashes, and U+00A0 becomes a backslash followed by "u00a0".
// After the escaping, a raw U+00A0 only ever appears as a separator.
const (
	execArgEscape       = `\`
	execArgEscapedSep   = execArgEscape + "u00a0"
	execArgEscapedSlash = `\\`
)

var (
	execArgEscaper   = strings.NewReplacer(execArgEscape, execArgEscapedSlash, igconsts.ArgsSeparator, execArgEscapedSep)
	execArgUnescaper = strings.NewReplacer(execArgEscapedSlash, execArgEscape, execArgEscapedSep, igconsts.ArgsSeparator)
)

// JoinExecArgs encodes argv into the single string carried by the exec
// datasource "args" field. SplitExecArgs reverses it.
func JoinExecArgs(args []string) string {
	escaped := make([]string, len(args))
	for i, arg := range args {
		escaped[i] = execArgEscaper.Replace(arg)
	}
	return strings.Join(escaped, igconsts.ArgsSeparator)
}

// SplitExecArgs decodes a string built by JoinExecArgs back into argv. An
// empty string yields nil (argv unknown).
func SplitExecArgs(joined string) []string {
	if joined == "" {
		return nil
	}
	args := strings.Split(joined, igconsts.ArgsSeparator)
	for i, arg := range args {
		if strings.Contains(arg, execArgEscape) {
			args[i] = execArgUnescaper.Replace(arg)
		}
	}
	return args
}
