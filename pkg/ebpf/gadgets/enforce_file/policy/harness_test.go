// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cHarness compiles ../../common/policy.h and ../file_policy.h, unchanged
// apart from their includes, with native helper substitutes
// (testdata/harness_head.h, testdata/harness.c).
func cHarness(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("the native matcher harness requires a C compiler")
	}
	var src strings.Builder
	for _, path := range []string{"testdata/harness_head.h", "../../common/policy.h", "../file_policy.h", "testdata/harness.c"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(path, "testdata/") && strings.HasPrefix(strings.TrimSpace(line), "#include") {
				continue
			}
			src.WriteString(line)
			src.WriteByte('\n')
		}
	}
	dir := t.TempDir()
	file, bin := filepath.Join(dir, "harness.c"), filepath.Join(dir, "harness")
	if err := os.WriteFile(file, []byte(src.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-Wno-fixed-enum-extension", "-o", bin, file).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return bin
}

type probe struct {
	slot      uint32
	fromImage bool
	path      string
}

// runHarness returns, per probe, the harness output line.
func runHarness(t *testing.T, bin string, c Compiled, probes []probe) []string {
	t.Helper()
	var blob bytes.Buffer
	write := func(v any) {
		if err := binary.Write(&blob, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	write(uint32(len(c.Slots)))
	write(c.Slots)
	write(uint32(len(c.Literals)))
	write(c.Literals)
	file := filepath.Join(t.TempDir(), "maps.bin")
	if err := os.WriteFile(file, blob.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var in strings.Builder
	for _, p := range probes {
		fi := 0
		if p.fromImage {
			fi = 1
		}
		fmt.Fprintf(&in, "%d %d %s\n", p.slot, fi, p.path)
	}
	cmd := exec.Command(bin, file)
	cmd.Stdin = strings.NewReader(in.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 1<<20)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != len(probes)+1 {
		t.Fatalf("harness printed %d lines for %d probes", len(lines), len(probes))
	}
	if want := fmt.Sprintf("hash %x", hashVector); lines[0] != want {
		t.Fatalf("C hash vector: %s, want %s", lines[0], want)
	}
	return lines[1:]
}

// expected is what the Go simulator says for one probe, in harness format.
func expected(s *sim, p probe) string {
	if s.c.Slots[p.slot].Mode == KernelModeOff {
		return "off"
	}
	m := s.match(p.slot, p.path)
	line := fmt.Sprintf("%x %x %x %x", m[0], m[1], m[2], m[3])
	for a := 0; a <= AccessMoveSource; a++ {
		o := s.decide(p.slot, a, m, p.fromImage)
		d := 0
		if o.isDefault {
			d = 1
		}
		line += fmt.Sprintf(" %d %d %d", o.rank, o.ruleID, d)
	}
	return line
}

// TestCMatcherEqualsGo runs the C matcher and decision of ../file_policy.h
// and the Go simulator on the same compiled maps and paths.
func TestCMatcherEqualsGo(t *testing.T) {
	bin := cHarness(t)
	r := rand.New(rand.NewSource(2))
	example := example(t)
	audit := rules50(t)
	audit.Name, audit.Policy.Mode = "audit", "audit"
	off := example
	off.Policy.Mode, off.Policy.File.Rules = "off", nil
	classes := Document{Version: 1, Name: "classes", Policy: Policy{Mode: "enforce", File: Section{Defaults: allDefaults("allow")}}}
	for i, c := range classCases {
		classes.Policy.File.Rules = append(classes.Policy.File.Rules, Rule{Name: fmt.Sprint(i), Action: "deny", Paths: []string{c.pattern}})
	}
	sets := [][][]Document{
		{{example}, {rules50(t)}, {classes}, {example, audit}, {off}},
	}
	for i := 0; i < 10; i++ {
		var slots [][]Document
		for j := 0; j < 3; j++ {
			d := Document{Version: 1, Name: fmt.Sprint(j), Policy: Policy{Mode: "enforce", File: Section{Defaults: allDefaults("allow")}}}
			for k, p := range randomPatterns(r, 20) {
				action := []string{"allow", "deny"}[r.Intn(2)]
				rule := Rule{Name: fmt.Sprint(k), Action: action, Paths: []string{p}, FromImage: r.Intn(5) == 0,
					Access: []string{AccessKinds[r.Intn(KernelAccessKinds)]}}
				if action == "deny" && r.Intn(4) == 0 {
					rule.Except = randomPatterns(r, 1)
				}
				d.Policy.File.Rules = append(d.Policy.File.Rules, rule)
			}
			d.Policy.File.Defaults[AccessKinds[r.Intn(KernelAccessKinds)]] = Default{Action: "deny"}
			slots = append(slots, []Document{d})
		}
		sets = append(sets, slots)
	}
	paths := append(randomPaths(r, 300),
		"/", "/etc/shadow", "/workspace/.claude/settings.local.json", "/workspace/.claude/settings.json",
		"/run/containerd/s/abc.sock", "/usr/lib/python3.11/site-packages/x.py", "/etc/cron.daily/x",
		"/dev/pts/0", "/home/bob/.ssh/id_rsa", "/a/"+strings.Repeat("long-component-", 16)+"/b",
		"/"+strings.Repeat("d/", 1000)+"x")
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, "testdata/match_cases.txt")), "\n") {
		if f := strings.Fields(line); len(f) == 3 && !strings.HasPrefix(line, "#") {
			paths = append(paths, f[1])
		}
	}
	total := 0
	for _, set := range sets {
		c, err := CompileSlots(set, 7)
		if err != nil {
			t.Fatal(err)
		}
		s := newSim(c)
		var probes []probe
		for slot := range set {
			for _, p := range paths {
				probes = append(probes, probe{uint32(slot), false, p}, probe{uint32(slot), true, p})
			}
		}
		got := runHarness(t, bin, c, probes)
		for i, p := range probes {
			if want := expected(s, p); got[i] != want {
				t.Fatalf("slot %d fromImage %v %s:\n C:  %s\n Go: %s", p.slot, p.fromImage, p.path, got[i], want)
			}
		}
		total += len(probes)
	}
	t.Logf("%d probes equal in C and Go", total)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
