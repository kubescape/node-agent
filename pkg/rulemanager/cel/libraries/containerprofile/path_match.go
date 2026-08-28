package containerprofile

import (
	"strings"
)

// matchLiteralPath performs an O(1) membership check of query against a set of
// literal paths (Values), matching the trailing-slash semantics of CompareDynamic:
// - Exact match: values[query]
// - Single trailing slash equivalence: "/etc/passwd/" <-> "/etc/passwd" (query != "/")
// - Multiple trailing slashes (e.g. "//" or "...//") and empty strings ("") are not normalized.
func matchLiteralPath(values map[string]struct{}, query string) bool {
	if query == "" || len(values) == 0 {
		return false
	}
	if _, ok := values[query]; ok {
		return true
	}
	if query != "/" && !strings.HasSuffix(query, "//") {
		if strings.HasSuffix(query, "/") {
			trimmed := strings.TrimSuffix(query, "/")
			if trimmed != "" && !strings.HasSuffix(trimmed, "/") {
				if _, ok := values[trimmed]; ok {
					return true
				}
			}
		} else {
			if _, ok := values[query+"/"]; ok {
				return true
			}
		}
	}
	return false
}
