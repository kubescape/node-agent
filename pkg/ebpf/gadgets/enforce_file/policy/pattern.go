// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"fmt"
	"strings"
)

// SegmentKind is the kind of one `/`-separated pattern segment.
type SegmentKind uint8

const (
	SegLiteral    SegmentKind = iota // one component, exactly
	SegStar                          // `*`: one whole component
	SegDoubleStar                    // `**`: zero or more components
	SegGlob                          // `pre*suf`: one component with that prefix and suffix
)

// Segment is one pattern segment. Lit is the literal; Pre and Suf are the
// parts of a glob.
type Segment struct {
	Kind     SegmentKind
	Lit      string
	Pre, Suf string
}

func (s Segment) String() string {
	switch s.Kind {
	case SegStar:
		return "*"
	case SegDoubleStar:
		return "**"
	case SegGlob:
		return s.Pre + "*" + s.Suf
	}
	return s.Lit
}

// Pattern is one parsed and normalised path glob.
type Pattern struct {
	Segments []Segment
}

// String returns the normalised form: "/" and the segments.
func (p Pattern) String() string {
	parts := make([]string, len(p.Segments))
	for i, s := range p.Segments {
		parts[i] = s.String()
	}
	return "/" + strings.Join(parts, "/")
}

// ParsePattern parses and normalises one path glob (see README "Patterns"):
// an absolute path, or one that starts with `**`; segments are literals,
// `*`, `**`, or a literal with one `*` inside (prefix and suffix at most
// FILE_GLOB_PART_MAX bytes each). `**x` is normalised to `**/*x` and
// consecutive `**` collapse. Rejected: `?`, `[`, `]`, more than one `*` in a
// segment, empty, `.` or `..` segments, relative paths.
func ParsePattern(s string) (Pattern, error) {
	var p Pattern
	if len(s) > KernelPathMax {
		return p, fmt.Errorf("pattern longer than %d bytes", KernelPathMax)
	}
	rest, ok := strings.CutPrefix(s, "/")
	if !ok && !strings.HasPrefix(s, "**") {
		return p, fmt.Errorf("pattern must be absolute or start with **")
	}
	if rest == "" {
		return p, fmt.Errorf("pattern has no segment")
	}
	if strings.ContainsAny(s, "?[]\x00") {
		return p, fmt.Errorf("?, [ and ] are not supported")
	}
	add := func(seg Segment) {
		if seg.Kind == SegDoubleStar && len(p.Segments) > 0 && p.Segments[len(p.Segments)-1].Kind == SegDoubleStar {
			return // consecutive ** collapse
		}
		p.Segments = append(p.Segments, seg)
	}
	for _, part := range strings.Split(rest, "/") {
		switch {
		case part == "":
			return p, fmt.Errorf("empty segment")
		case part == "." || part == "..":
			return p, fmt.Errorf("%q segments are not allowed", part)
		case len(part) > KernelNameMax:
			return p, fmt.Errorf("segment longer than %d bytes", KernelNameMax)
		case part == "**":
			add(Segment{Kind: SegDoubleStar})
			continue
		case part == "*":
			add(Segment{Kind: SegStar})
			continue
		}
		if tail, ok := strings.CutPrefix(part, "**"); ok {
			// `**.sock` is `**/*.sock`.
			if strings.Contains(tail, "*") {
				return p, fmt.Errorf("segment %q has more than one wildcard", part)
			}
			add(Segment{Kind: SegDoubleStar})
			part = "*" + tail
		}
		switch strings.Count(part, "*") {
		case 0:
			add(Segment{Kind: SegLiteral, Lit: part})
		case 1:
			pre, suf, _ := strings.Cut(part, "*")
			if len(pre) > KernelGlobPartMax || len(suf) > KernelGlobPartMax {
				return p, fmt.Errorf("segment %q: prefix and suffix around * may have at most %d bytes each", part, KernelGlobPartMax)
			}
			if pre == "" && suf == "" {
				add(Segment{Kind: SegStar})
			} else {
				add(Segment{Kind: SegGlob, Pre: pre, Suf: suf})
			}
		default:
			return p, fmt.Errorf("segment %q has more than one *", part)
		}
	}
	return p, nil
}

// MatchPath reports whether the pattern matches an absolute path, by the
// language's definition (a reference for tests and tools; the kernel uses the
// compiled NFA). "/" has no components.
func (p Pattern) MatchPath(path string) bool {
	var comps []string
	for _, c := range strings.Split(path, "/") {
		if c != "" {
			comps = append(comps, c)
		}
	}
	return matchSegments(p.Segments, comps)
}

func matchSegments(segs []Segment, comps []string) bool {
	if len(segs) == 0 {
		return len(comps) == 0
	}
	s := segs[0]
	if s.Kind == SegDoubleStar {
		for i := 0; i <= len(comps); i++ {
			if matchSegments(segs[1:], comps[i:]) {
				return true
			}
		}
		return false
	}
	if len(comps) == 0 {
		return false
	}
	c := comps[0]
	switch s.Kind {
	case SegLiteral:
		if c != s.Lit {
			return false
		}
	case SegGlob:
		if len(c) < len(s.Pre)+len(s.Suf) || !strings.HasPrefix(c, s.Pre) || !strings.HasSuffix(c, s.Suf) {
			return false
		}
	}
	return matchSegments(segs[1:], comps[1:])
}

// guardLengths returns the segment counts of a deny rule pattern's guard:
// the pattern and each shorter segment prefix that does not end with `**`
// (so `/home/*/.aws/**` guards `/home/*/.aws`, `/home/*` and `/home`). The
// prefix without a trailing `**` is skipped: the pattern already matches it.
// A parent above a leading `**` is not guarded. A prefix needs no bits of its
// own: its last segment bit is active at the end of the path exactly when the
// path matches the prefix.
func (p Pattern) guardLengths() []int {
	n := len(p.Segments)
	out := []int{n}
	for i := n - 1; i >= 1; i-- {
		if p.Segments[i-1].Kind == SegDoubleStar {
			continue
		}
		if i == n-1 && p.Segments[n-1].Kind == SegDoubleStar {
			continue
		}
		out = append(out, i)
	}
	return out
}

// Guards returns the guard of a deny rule pattern as patterns (see
// guardLengths).
func (p Pattern) Guards() []Pattern {
	var out []Pattern
	for _, n := range p.guardLengths() {
		out = append(out, Pattern{Segments: append([]Segment(nil), p.Segments[:n]...)})
	}
	return out
}
