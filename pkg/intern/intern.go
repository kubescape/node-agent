package intern

import "unique"

// String interns s so that all identical strings share backing memory.
// Returns a normal string — no type changes needed at call sites.
func String(s string) string {
	if s == "" {
		return ""
	}
	return unique.Make(s).Value()
}
