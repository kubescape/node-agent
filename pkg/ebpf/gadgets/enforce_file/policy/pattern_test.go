// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"strings"
	"testing"
)

func TestParsePatternNormalises(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/shadow":                        "/etc/shadow",
		"/work/**":                           "/work/**",
		"**/.claude/**":                      "/**/.claude/**",
		"/**/.claude/**":                     "/**/.claude/**",
		"/home/*/.aws/**":                    "/home/*/.aws/**",
		"/etc/cron*/**":                      "/etc/cron*/**",
		"/run/containerd/**.sock":            "/run/containerd/**/*.sock",
		"/a/**/**/b":                         "/a/**/b",
		"/a/**/**.sock":                      "/a/**/*.sock",
		"/dev/sd*":                           "/dev/sd*",
		"**":                                 "/**",
		"/usr/lib/python3*/site-packages/**": "/usr/lib/python3*/site-packages/**",
	} {
		p, err := ParsePattern(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if p.String() != want {
			t.Errorf("%s: normalised to %s, want %s", in, p.String(), want)
		}
	}
}

func TestParsePatternRejects(t *testing.T) {
	for _, in := range []string{
		"", "/", "relative/path", "./x", "*/x", "/a/?", "/a/[ab]", "/a/b]", "/a//b", "/a/", "/a/./b", "/a/../b",
		"/a/*b*", "/a/**b*", "/a/b**", "/" + strings.Repeat("p", 17) + "*", "/*" + strings.Repeat("s", 17),
		"/" + strings.Repeat("n", 256), "/" + strings.Repeat("a/", 2048) + "b",
	} {
		if p, err := ParsePattern(in); err == nil {
			t.Errorf("%q accepted as %s", in, p)
		}
	}
	// Prefix and suffix of 16 bytes each are the limit.
	if _, err := ParsePattern("/" + strings.Repeat("p", 16) + "*" + strings.Repeat("s", 16)); err != nil {
		t.Error(err)
	}
}

func TestGuards(t *testing.T) {
	for in, want := range map[string][]string{
		"/root/.aws/**":   {"/root"},
		"/home/*/.aws/**": {"/home/*", "/home"},
		"/etc/shadow":     {"/etc"},
		"**/.claude/**":   nil,
		"**/.git/config":  {"/**/.git"},
		"/a/**/b/c":       {"/a/**/b", "/a"},
		"/etc/cron*/**":   {"/etc"},
		"/x":              nil,
		"/**":             nil,
	} {
		p, err := ParsePattern(in)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, g := range p.Guards() {
			got = append(got, g.String())
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: guards %v, want %v", in, got, want)
		}
	}
}

func TestReferenceMatcher(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          bool
	}{
		{"/a/**", "/a", true},
		{"/a/**", "/a/b/c", true},
		{"/a/**", "/ab", false},
		{"/**", "/", true},
		{"**/x", "/x", true},
		{"**/x", "/a/b/x", true},
		{"**/x", "/a/x/b", false},
		{"/a/*", "/a", false},
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/c", false},
		{"/a/b*c", "/a/bc", true},
		{"/a/b*c", "/a/bxc", true},
		{"/a/bc*c", "/a/bcc", true},
		{"/a/bc*c", "/a/bc", false},
		{"/run/containerd/**.sock", "/run/containerd/x/y.sock", true},
		{"/run/containerd/**.sock", "/run/containerd/y.sock", true},
		{"/run/containerd/**.sock", "/run/containerd/y.sockx", false},
	} {
		p, err := ParsePattern(c.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.MatchPath(c.path); got != c.want {
			t.Errorf("%s on %s = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}
