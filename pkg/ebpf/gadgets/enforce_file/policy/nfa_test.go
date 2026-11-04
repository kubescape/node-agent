// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func allDefaults(action string) map[string]Default {
	m := map[string]Default{}
	for _, k := range AccessKinds {
		m[k] = Default{Action: action}
	}
	return m
}

// rules50 reads testdata/rules50.txt into one enforce document with a write
// default deny.
func rules50(t *testing.T) Document {
	t.Helper()
	f, err := os.Open("testdata/rules50.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := Document{Version: 1, Name: "spike", Policy: Policy{Mode: "enforce", File: Section{Defaults: allDefaults("allow")}}}
	d.Policy.File.Defaults[AccessWrite] = Default{Action: "deny"}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var action, access, path string
		if _, err := fmt.Sscan(line, &action, &access, &path); err != nil {
			t.Fatal(err)
		}
		kinds := map[string][]string{"rw": {AccessRead, AccessWrite}, "read": {AccessRead}, "write": {AccessWrite}}[access]
		d.Policy.File.Rules = append(d.Policy.File.Rules, Rule{Name: fmt.Sprintf("r%d", len(d.Policy.File.Rules)), Action: action, Access: kinds, Paths: []string{path}})
	}
	return d
}

func TestSpikeMatchCases(t *testing.T) {
	s := compileOne(t, rules50(t))
	f, err := os.Open("testdata/match_cases.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var access, path, want string
		if _, err := fmt.Sscan(line, &access, &path, &want); err != nil {
			t.Fatal(err)
		}
		kind := map[string]string{"r": AccessRead, "w": AccessWrite}[access]
		got := "allow"
		if s.judge(0, kind, path, false).rank >= RankDenyAudit {
			got = "deny"
		}
		if got != want {
			t.Errorf("%s %s = %s, want %s", access, path, got, want)
		}
		n++
	}
	if n != 20 {
		t.Fatalf("%d cases, want 20", n)
	}
}

// The default path classes of the policy language this gadget serves (the
// secrets directory name is neutral here), with paths each must and must not
// match.
var classCases = []struct {
	pattern string
	match   []string
	nomatch []string
}{
	{"/root/.aws/**", []string{"/root/.aws", "/root/.aws/credentials", "/root/.aws/sso/cache/x.json"}, []string{"/root/.awsx", "/root", "/home/root/.aws/x"}},
	{"/home/*/.aws/**", []string{"/home/bob/.aws/config", "/home/a/.aws"}, []string{"/home/.aws/x", "/home/a/b/.aws/x"}},
	{"/var/run/secrets/example.io/serviceaccount/token", []string{"/var/run/secrets/example.io/serviceaccount/token"}, []string{"/var/run/secrets/example.io/serviceaccount/token2", "/run/secrets/example.io/serviceaccount/token"}},
	{"**/.netrc", []string{"/.netrc", "/root/.netrc", "/a/b/c/.netrc"}, []string{"/root/.netrc/x", "/root/x.netrc"}},
	{"**/.docker/config.json", []string{"/root/.docker/config.json", "/.docker/config.json"}, []string{"/root/.docker/config.json.bak", "/root/docker/config.json"}},
	{"**/.env", []string{"/app/.env"}, []string{"/app/.envrc", "/app/x.env"}},
	{"/root/.ssh/**", []string{"/root/.ssh/id_rsa"}, []string{"/root/.sshd/x"}},
	{"/root/.config/gcloud/**", []string{"/root/.config/gcloud/credentials.db"}, []string{"/root/.config/gcloudx"}},
	{"/root/.bashrc", []string{"/root/.bashrc"}, []string{"/root/.bashrc.d/x", "/home/a/.bashrc"}},
	{"/etc/profile.d/**", []string{"/etc/profile.d/x.sh", "/etc/profile.d"}, []string{"/etc/profile"}},
	{"**/.claude/**", []string{"/work/.claude/settings.json", "/.claude", "/a/b/.claude/c/d"}, []string{"/work/x.claude/y", "/work/.claudex/y"}},
	{"**/CLAUDE.md", []string{"/work/CLAUDE.md", "/CLAUDE.md"}, []string{"/work/CLAUDE.md/x", "/work/XCLAUDE.md"}},
	{"/etc/cron*/**", []string{"/etc/cron.d/x", "/etc/crontab", "/etc/cron.daily/logrotate", "/etc/cron"}, []string{"/etc/xcron.d/x", "/etc/cro"}},
	{"/etc/rc*.d/**", []string{"/etc/rc0.d/K01x", "/etc/rc.d", "/etc/rcS.d/x"}, []string{"/etc/rc.local", "/etc/rcd"}},
	{"/etc/ld.so.preload", []string{"/etc/ld.so.preload"}, []string{"/etc/ld.so.preload2"}},
	{"/usr/lib/python3*/site-packages/**", []string{"/usr/lib/python3.11/site-packages/x/y.py", "/usr/lib/python3/site-packages"}, []string{"/usr/lib/python2.7/site-packages/x", "/usr/lib/python3.11/dist-packages/x"}},
	{"/usr/local/lib/python3*/**", []string{"/usr/local/lib/python3.12/x"}, []string{"/usr/local/lib/python/x"}},
	{"**/node_modules/**", []string{"/app/node_modules/x/index.js", "/node_modules"}, []string{"/app/node_modules2/x"}},
	{"/run/containerd/**.sock", []string{"/run/containerd/containerd.sock", "/run/containerd/s/abc.sock"}, []string{"/run/containerd/containerd.sock.ttrpc", "/run/containerd"}},
	{"/var/run/docker.sock", []string{"/var/run/docker.sock"}, []string{"/run/docker.sock"}},
	{"/dev/sd*", []string{"/dev/sda", "/dev/sd"}, []string{"/dev/sda/x", "/dev/xsda"}},
	{"/dev/nvme*", []string{"/dev/nvme0n1"}, []string{"/dev/nvm"}},
	{"/dev/kmsg", []string{"/dev/kmsg"}, []string{"/dev/kmsg1"}},
}

func TestDefaultClassPatterns(t *testing.T) {
	d := Document{Version: 1, Policy: Policy{Mode: "enforce", File: Section{Defaults: allDefaults("allow")}}}
	for i, c := range classCases {
		d.Policy.File.Rules = append(d.Policy.File.Rules, Rule{Name: fmt.Sprint(i), Action: "deny", Paths: []string{c.pattern}})
	}
	comp, err := CompileKernel(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := newSim(comp)
	for i, c := range classCases {
		p, _ := ParsePattern(c.pattern)
		rule := comp.Slots[0].Rules[i]
		for _, path := range c.match {
			if !s.match(0, path).intersects(rule.Match) || !p.MatchPath(path) {
				t.Errorf("%s must match %s", c.pattern, path)
			}
		}
		for _, path := range c.nomatch {
			if s.match(0, path).intersects(rule.Match) || p.MatchPath(path) {
				t.Errorf("%s must not match %s", c.pattern, path)
			}
		}
	}
}

// randomPatterns and randomPaths draw from small alphabets so literals, globs
// and wildcards collide often.
var (
	patternSegs = []string{"a", "b", "ab", "x.sock", "*", "**", "a*", "*b", "a*b", "ca*", "**.sock", ".c"}
	pathComps   = []string{"a", "b", "ab", "abb", "x.sock", "c", "cab", "ca", ".c", "aab", "y.sock"}
)

func randomPatterns(r *rand.Rand, n int) []string {
	var out []string
	for len(out) < n {
		var segs []string
		for k := 1 + r.Intn(5); k > 0; k-- {
			segs = append(segs, patternSegs[r.Intn(len(patternSegs))])
		}
		p := "/" + strings.Join(segs, "/")
		if r.Intn(4) == 0 && segs[0] != "**" && !strings.HasPrefix(segs[0], "**") {
			p = "**" + p
		}
		if _, err := ParsePattern(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func randomPaths(r *rand.Rand, n int) []string {
	out := []string{"/"}
	for len(out) < n {
		var comps []string
		for k := r.Intn(7); k > 0; k-- {
			comps = append(comps, pathComps[r.Intn(len(pathComps))])
		}
		out = append(out, "/"+strings.Join(comps, "/"))
	}
	return out
}

// patternSlot compiles patterns as deny rules (one per pattern) in one slot.
func patternSlot(t *testing.T, patterns []string) Compiled {
	t.Helper()
	d := Document{Version: 1, Policy: Policy{Mode: "enforce", File: Section{Defaults: allDefaults("allow")}}}
	for i, p := range patterns {
		d.Policy.File.Rules = append(d.Policy.File.Rules, Rule{Name: fmt.Sprint(i), Action: "deny", Paths: []string{p}})
	}
	c, err := CompileKernel(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestNFAAgainstReference runs the kernel step function (Go copy) over many
// paths and patterns and compares with the reference matcher, for the rule
// patterns and for their guards.
func TestNFAAgainstReference(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	paths := randomPaths(r, 400)
	checks := 0
	for round := 0; round < 40; round++ {
		patterns := randomPatterns(r, 20)
		c := patternSlot(t, patterns)
		s := newSim(c)
		for _, path := range paths {
			m := s.match(0, path)
			for i, ps := range patterns {
				p, _ := ParsePattern(ps)
				rule := c.Slots[0].Rules[i]
				if got, want := m.intersects(rule.Match), p.MatchPath(path); got != want {
					t.Fatalf("%s on %s: NFA %v, reference %v", ps, path, got, want)
				}
				guarded := false
				for _, g := range p.Guards() {
					guarded = guarded || g.MatchPath(path)
				}
				if got := m.intersects(rule.Guard); got != guarded {
					t.Fatalf("guard of %s on %s: NFA %v, reference %v", ps, path, got, guarded)
				}
				checks++
			}
		}
	}
	t.Logf("%d pattern x path checks", checks)
}
