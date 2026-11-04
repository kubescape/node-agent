// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestKernelLayout(t *testing.T) {
	for name, c := range map[string]struct{ got, want int }{
		"file_slot":        {binary.Size(SlotValue{}), KernelSlotSize},
		"file_literal_key": {binary.Size(LiteralKey{}), KernelLiteralKeySize},
		"file_bits":        {binary.Size(Bits{}), KernelLiteralValueSize},
		"policy_value":     {binary.Size(PolicyValue{}), 24},
		"file_glob":        {binary.Size(GlobEntry{}), 56},
		"file_rule":        {binary.Size(RuleEntry{}), 112},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d bytes, want %d", name, c.got, c.want)
		}
	}
}

// TestKernelConstantsMatchHeader reads the defines of ../file_policy.h.
func TestKernelConstantsMatchHeader(t *testing.T) {
	data, err := os.ReadFile("../file_policy.h")
	if err != nil {
		t.Fatal(err)
	}
	defines := map[string]uint64{}
	for _, m := range regexp.MustCompile(`(?m)^#define (\w+) (0x[0-9a-fA-F]+|\d+)(ULL)?\b`).FindAllStringSubmatch(string(data), -1) {
		v, err := strconv.ParseUint(m[2], 0, 64)
		if err != nil {
			t.Fatal(err)
		}
		defines[m[1]] = v
	}
	for name, want := range map[string]uint64{
		"FILE_MAX_SLOTS": KernelMaxSlots, "FILE_SEG_BITS": KernelSegBits, "FILE_SEG_WORDS": KernelSegWords,
		"FILE_MAX_RULES": KernelMaxRules, "FILE_MAX_GLOBS": KernelMaxGlobs, "FILE_MAX_LITERALS": KernelMaxLiterals,
		"FILE_GLOB_PART_MAX": KernelGlobPartMax, "FILE_MAX_DOCS": KernelMaxDocs, "FILE_ACCESS_KINDS": KernelAccessKinds,
		"FILE_PATH_MAX": KernelPathMax, "FILE_NAME_MAX": KernelNameMax, "FILE_FNV_PRIME": FNVPrime,
		"FILE_RULE_FROM_IMAGE": RuleFromImage, "FILE_RULE_ANY_PATH": RuleAnyPath, "FILE_RULE_GUARD": RuleGuard,
		"FILE_RULE_ID_DEFAULT": RuleIDDefault, "FILE_RULE_ID_UNRESOLVED": RuleIDUnresolved,
	} {
		got, ok := defines[name]
		if !ok || got != want {
			t.Errorf("%s = %d (defined %v), Go has %d", name, got, ok, want)
		}
	}
}

func TestHashVector(t *testing.T) {
	// Shared with the C harness (harness_test.go).
	if got := Hash(0x0123456789abcdef, "credentials"); got != hashVector {
		t.Fatalf("Hash = %#x, want %#x", got, hashVector)
	}
	// With the standard offset basis the function is plain FNV-1a 64.
	if got := Hash(0xcbf29ce484222325, "a"); got != 0xaf63dc4c8601ec8c {
		t.Fatalf("FNV-1a(a) = %#x", got)
	}
	if HashReverse(7, "ab") != Hash(7, "ba") {
		t.Fatal("HashReverse must hash the bytes backwards")
	}
}

const hashVector uint64 = 0xd16de21c7ab52a6f

func example(t *testing.T) Document {
	t.Helper()
	f, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestExamplePolicy(t *testing.T) {
	d := example(t)
	c, err := CompileKernel(d, 3)
	if err != nil {
		t.Fatal(err)
	}
	s := newSim(c)
	for _, tc := range []struct {
		access, path string
		fromImage    bool
		want         uint8
		rule         string
	}{
		{AccessRead, "/etc/passwd", true, RankAllow, "default"},
		{AccessRead, "/etc/shadow", true, RankDenyEnforce, "example/no-secrets-read"},
		{AccessWrite, "/workspace/a.txt", false, RankAllow, "example/workspace"},
		{AccessWrite, "/etc/motd", false, RankDenyEnforce, "default"},
		{AccessWrite, "/etc/motd", true, RankDenyEnforce, "example/no-image-tamper"},
		{AccessWrite, "/var/log/x", false, RankDenyEnforce, "default"},
		{AccessWrite, "/workspace/.claude/settings.json", false, RankDenyEnforce, "example/no-agent-config"},
		{AccessWrite, "/workspace/.claude/settings.local.json", false, RankAllow, "example/workspace"},
		{AccessCreate, "/tmp/new", false, RankAllow, "example/workspace"},
		{AccessCreate, "/new", false, RankDenyEnforce, "default"},
		{AccessChmod, "/usr/bin/ls", true, RankDenyEnforce, "example/no-image-tamper"},
		{AccessChmod, "/tmp/x", false, RankDenyAudit, "default"},
		{AccessWrite, "/dev/null", false, RankAllow, "example/devices"},
	} {
		got := s.judge(0, tc.access, tc.path, tc.fromImage)
		if got.rank != tc.want || c.RuleNames[got.ruleID] != tc.rule {
			t.Errorf("%s %s (fromImage %v) = rank %d by %s, want %d by %s", tc.access, tc.path, tc.fromImage,
				got.rank, c.RuleNames[got.ruleID], tc.want, tc.rule)
		}
	}
}

func doc(defaults map[string]Default, rules ...Rule) Document {
	return Document{Version: 1, Name: "d", Policy: Policy{Mode: "enforce", File: Section{Defaults: defaults, Rules: rules}}}
}

func TestGuardAndExcept(t *testing.T) {
	d := doc(allDefaults("allow"),
		Rule{Name: "aws", Action: "deny", Access: []string{AccessRead}, Paths: []string{"/root/.aws/**"}},
		Rule{Name: "cfg", Action: "deny", Mode: "audit", Access: []string{AccessWrite}, Paths: []string{"**/.claude/**"},
			Except: []string{"/w/.claude/ok"}},
		Rule{Name: "img", Action: "deny", Access: []string{AccessWrite}, FromImage: true},
		Rule{Name: "ok", Action: "allow", Paths: []string{"/w/**"}},
	)
	c, err := CompileKernel(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := newSim(c)
	guard := func(path string, fromImage bool) (uint8, string) {
		o := s.decide(0, AccessMoveSource, s.match(0, path), fromImage)
		return o.rank, c.RuleNames[o.ruleID]
	}
	for _, tc := range []struct {
		path      string
		fromImage bool
		rank      uint8
		rule      string
	}{
		{"/root/.aws/credentials", false, RankDenyEnforce, "d/aws"},
		{"/root/.aws", false, RankDenyEnforce, "d/aws"},
		{"/root", false, RankDenyEnforce, "d/aws"},
		{"/", false, RankNone, ""},
		{"/rootx", false, RankNone, ""},
		{"/w/.claude/x", false, RankDenyAudit, "d/cfg"},
		{"/w/.claude/ok", false, RankNone, ""},
		{"/w/file", true, RankDenyEnforce, "d/img"},
		{"/w/file", false, RankNone, ""},
	} {
		rank, rule := guard(tc.path, tc.fromImage)
		if rank != tc.rank || rule != tc.rule {
			t.Errorf("guard %s = %d %s, want %d %s", tc.path, rank, rule, tc.rank, tc.rule)
		}
	}
	// Except lifts only that rule; the allow then decides.
	if got := s.judge(0, AccessWrite, "/w/.claude/ok", false); got.rank != RankAllow {
		t.Errorf("except: rank %d", got.rank)
	}
	v := c.Slots[0]
	if v.Unresolved[accessIndex(AccessRead)] != RankDenyEnforce || v.Unresolved[accessIndex(AccessCreate)] != RankAllow ||
		v.Unresolved[AccessMoveSource] != RankDenyEnforce || v.Unresolved[accessIndex(AccessWrite)] != RankDenyEnforce {
		t.Errorf("unresolved ranks %v", v.Unresolved)
	}
}

func TestDefaultsPerAccess(t *testing.T) {
	a := doc(map[string]Default{AccessRead: {Action: "allow"}, AccessWrite: {Action: "deny", Origin: "o/w"},
		AccessCreate: {Action: "deny", Mode: "audit"}, AccessDelete: {Action: "allow"}, AccessRename: {Action: "allow"},
		AccessChmod: {Action: "allow"}})
	b := doc(allDefaults("allow"))
	b.Name, b.Policy.Mode = "b", "audit"
	b.Policy.File.Defaults[AccessDelete] = Default{Action: "deny"}
	off := doc(allDefaults("deny"))
	off.Policy.Mode = "off"
	c, err := CompileSlots([][]Document{{a, b}, {off}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Slots[0]
	want := map[string]uint8{AccessRead: RankAllow, AccessWrite: RankDenyEnforce, AccessCreate: RankDenyAudit,
		AccessDelete: RankDenyAudit, AccessRename: RankAllow, AccessChmod: RankAllow}
	for k, r := range want {
		if got := v.Defaults[accessIndex(k)]; got.Rank != r || got.RuleID != RuleIDDefault {
			t.Errorf("default %s = %+v, want rank %d", k, got, r)
		}
	}
	if v.DenyEnforceDocs[accessIndex(AccessWrite)] != 1 || v.DenyEnforceDocs[accessIndex(AccessCreate)] != 0 {
		t.Errorf("deny enforce docs %v", v.DenyEnforceDocs)
	}
	if c.Origins[v.Defaults[accessIndex(AccessWrite)].OriginID] != "o/w" {
		t.Error("the default keeps its origin")
	}
	if v.Mode != KernelModeEnforce || v.Generation != 9 || c.Slots[1].Mode != KernelModeOff {
		t.Errorf("modes %d %d", v.Mode, c.Slots[1].Mode)
	}
}

func TestCompileLimits(t *testing.T) {
	ok := doc(allDefaults("allow"), Rule{Name: "r", Action: "deny", Paths: []string{"/a"}})
	if _, err := CompileKernel(ok, 0); err == nil {
		t.Error("generation 0 accepted")
	}
	slots := make([][]Document, KernelMaxSlots+1)
	for i := range slots {
		slots[i] = []Document{ok}
	}
	if _, err := CompileSlots(slots, 1); err == nil {
		t.Error("too many slots accepted")
	}
	if _, err := CompileSlots(slots[:KernelMaxSlots], 1); err != nil {
		t.Error(err)
	}
	var many []Rule
	for i := 0; i <= KernelMaxRules; i++ {
		many = append(many, Rule{Name: fmt.Sprint(i), Action: "allow", Paths: []string{"/a"}})
	}
	if _, err := CompileKernel(doc(allDefaults("allow"), many...), 1); err == nil || !strings.Contains(err.Error(), "rules") {
		t.Errorf("too many rules: %v", err)
	}
	if _, err := CompileKernel(doc(allDefaults("allow"), many[:KernelMaxRules]...), 1); err != nil {
		t.Error(err)
	}
	deep := "/" + strings.Repeat("x/", 64) + "y"
	var wide []string
	for i := 0; i < 4; i++ {
		wide = append(wide, deep+fmt.Sprint(i))
	}
	if _, err := CompileKernel(doc(allDefaults("allow"), Rule{Name: "w", Action: "allow", Paths: wide}), 1); err == nil || !strings.Contains(err.Error(), "segments") {
		t.Errorf("too many segments: %v", err)
	}
	var globs []string
	for i := 0; i <= KernelMaxGlobs; i++ {
		globs = append(globs, fmt.Sprintf("/g%d*", i))
	}
	if _, err := CompileKernel(doc(allDefaults("allow"), Rule{Name: "g", Action: "allow", Paths: globs}), 1); err == nil || !strings.Contains(err.Error(), "glob") {
		t.Errorf("too many globs: %v", err)
	}
	var docs []Document
	for i := 0; i <= KernelMaxDocs; i++ {
		docs = append(docs, ok)
	}
	if _, err := CompileSlots([][]Document{docs}, 1); err == nil {
		t.Error("too many policies accepted")
	}
	// The same pattern in many rules uses its bits once.
	var same []Rule
	for i := 0; i < KernelMaxRules; i++ {
		same = append(same, Rule{Name: fmt.Sprint(i), Action: "deny", Paths: []string{deep + "0"}})
	}
	if _, err := CompileKernel(doc(allDefaults("allow"), same...), 1); err != nil {
		t.Errorf("deduplicated patterns: %v", err)
	}
}

func TestSeedAndLiterals(t *testing.T) {
	old := randomSeed
	defer func() { randomSeed = old }()
	randomSeed = func() (uint64, error) { return 42, nil }
	c, err := CompileKernel(doc(allDefaults("allow"), Rule{Name: "r", Action: "deny", Paths: []string{"/a/b", "/b/a", "/a*z"}}), 1)
	if err != nil {
		t.Fatal(err)
	}
	if c.Slots[0].Seed != 42 || len(c.Literals) != 2 || c.Slots[0].NGlobs != 1 {
		t.Fatalf("seed %d, %d literals, %d globs", c.Slots[0].Seed, len(c.Literals), c.Slots[0].NGlobs)
	}
	for _, l := range c.Literals {
		// "a" is the first segment of /a/b and the last of /b/a: both bits.
		if l.Key.Hash == Hash(42, "a") && (l.Bits[0] != 1<<0|1<<3) {
			t.Errorf("literal a bits %#x", l.Bits[0])
		}
	}
	g := c.Slots[0].Globs[0]
	if g.PreHash != Hash(42, "a") || g.SufHash != Hash(42, "z") || g.PreLen != 1 || g.SufLen != 1 {
		t.Errorf("glob %+v", g)
	}
}

func TestRule5PerAccessKind(t *testing.T) {
	// A write default deny in enforce mode survives another policy's audit
	// deny on write, but not on read, where its default allows.
	strict := doc(map[string]Default{AccessRead: {Action: "allow"}, AccessWrite: {Action: "deny"}, AccessCreate: {Action: "allow"},
		AccessDelete: {Action: "allow"}, AccessRename: {Action: "allow"}, AccessChmod: {Action: "allow"}})
	audit := doc(allDefaults("allow"), Rule{Name: "x", Action: "deny", Paths: []string{"/x"}})
	audit.Name, audit.Policy.Mode = "audit", "audit"
	c, err := CompileSlots([][]Document{{audit, strict}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := newSim(c)
	if got := s.judge(0, AccessWrite, "/x", false); got.rank != RankDenyEnforce || !got.isDefault {
		t.Errorf("write: %+v", got)
	}
	if got := s.judge(0, AccessRead, "/x", false); got.rank != RankDenyAudit || got.isDefault {
		t.Errorf("read: %+v", got)
	}
}
