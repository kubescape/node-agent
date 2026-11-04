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
		"FILE_RULE_NEW_NAME_GUARD": RuleNewNameGuard, "FILE_RULE_ID_DEFAULT": RuleIDDefault, "FILE_RULE_ID_UNRESOLVED": RuleIDUnresolved,
		"FILE_SLOT_FROM_IMAGE": SlotFromImage,
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
		Rule{Name: "mode", Action: "deny", Access: []string{AccessChmod}, Paths: []string{"/etc/**"}},
		Rule{Name: "ok", Action: "allow", Paths: []string{"/w/**"}},
	)
	c, err := CompileKernel(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := newSim(c)
	for _, tc := range []struct {
		path      string
		fromImage bool
		rank      uint8
		rule      string
		access    int
	}{
		// The full decision of read: the rule's own paths.
		{"/root/.aws/credentials", false, RankDenyEnforce, "d/aws", 0},
		{"/root/.aws", false, RankDenyEnforce, "d/aws", 0},
		// The guard: a parent directory written in the pattern.
		{"/root", false, RankDenyEnforce, "d/aws", AccessMoveSource},
		{"/", false, RankAllow, "default", 0},
		{"/rootx", false, RankAllow, "default", 0},
		{"/w/.claude/x", false, RankDenyAudit, "d/cfg", 1},
		{"/w/.claude/ok", false, RankAllow, "d/ok", 0},
		{"/w/file", true, RankDenyEnforce, "d/img", 1},
		{"/w/file", false, RankAllow, "d/ok", 0},
		// A chmod rule neither judges nor guards a move.
		{"/etc/foo", false, RankAllow, "default", 0},
		{"/etc", false, RankAllow, "default", 0},
	} {
		o, access := s.moveSource(0, tc.path, tc.fromImage)
		if o.rank != tc.rank || c.RuleNames[o.ruleID] != tc.rule || access != tc.access {
			t.Errorf("move source %s (fromImage %v) = %d %s access %d, want %d %s access %d", tc.path, tc.fromImage,
				o.rank, c.RuleNames[o.ruleID], access, tc.rank, tc.rule, tc.access)
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
	// Only the read deny has parents to guard (cfg starts with **, img and
	// mode have no read or write paths).
	for i, r := range v.Rules[:v.NRules] {
		if guard := r.Flags&RuleGuard != 0; guard != (i == 0) {
			t.Errorf("rule %s: guard flag %v", c.RuleNames[r.RuleID], guard)
		}
	}
}

// TestMoveSources covers the moves of review findings 3 to 5: a move is judged
// by what the old name allows (rename, read, write), not by every deny rule.
func TestMoveSources(t *testing.T) {
	writeDeny := allDefaults("allow")
	writeDeny[AccessWrite] = Default{Action: "deny"}
	noDelete := Rule{Name: "nodel", Action: "deny", Access: []string{AccessDelete}, Paths: []string{"/**"}}
	noChmod := Rule{Name: "nochmod", Action: "deny", Access: []string{AccessChmod}, Paths: []string{"/etc/**"}}
	tmp := Rule{Name: "tmp", Action: "allow", Access: []string{AccessCreate, AccessWrite, AccessDelete}, Paths: []string{"/tmp/**"}}
	rename, create := 1<<accessIndex(AccessRename), 1<<accessIndex(AccessCreate)
	awsConfig := Rule{Name: "aws", Action: "deny", Access: []string{AccessWrite, AccessCreate}, Paths: []string{"/root/.aws/config"}}
	awsRead := Rule{Name: "aws", Action: "deny", Access: []string{AccessRead}, Paths: []string{"/root/.aws/**"}}
	preload := Rule{Name: "preload", Action: "deny", Access: []string{AccessWrite}, Paths: []string{"/etc/ld.so.preload"}}
	for _, tc := range []struct {
		name  string
		d     Document
		mask  int
		path  string
		rank  uint8
		rule  string
		which int
	}{
		// A pathless delete-only deny (the owner writes /**) does not stop a
		// rename or a hard link; it judges a replaced new name.
		{"pathless delete, old name", doc(allDefaults("allow"), noDelete), MoveSourceMask, "/workspace/a.txt", RankAllow, "default", 0},
		{"pathless delete, new name", doc(allDefaults("allow"), noDelete), rename | create, "/workspace/b.txt", RankAllow, "default", 2},
		{"pathless delete, replaced name", doc(allDefaults("allow"), noDelete), rename | ReplacedMask, "/workspace/b.txt", RankDenyEnforce, "d/nodel", 3},
		// sed -i under a chmod deny on /etc/**: a temporary file renamed over
		// the original.
		{"chmod deny, sed -i old name", doc(allDefaults("allow"), noChmod), MoveSourceMask, "/etc/sedAbc123", RankAllow, "default", 0},
		{"chmod deny, sed -i new name", doc(allDefaults("allow"), noChmod), rename | ReplacedMask, "/etc/foo", RankAllow, "default", 1},
		// ln /etc/passwd /tmp/p under a write default deny with rename
		// allowed: the old name is not writable.
		{"hard link out of a write deny", doc(writeDeny, tmp), MoveSourceMask, "/etc/passwd", RankDenyEnforce, "default", 1},
		{"hard link inside the workspace", doc(writeDeny, tmp), MoveSourceMask, "/tmp/a", RankAllow, "default", 0},
		// RENAME_EXCHANGE of /tmp/evil and /etc/passwd: both names are moved
		// and replaced.
		{"exchange, protected name", doc(writeDeny, tmp), MoveSourceMask | ReplacedMask, "/etc/passwd", RankDenyEnforce, "default", 1},
		{"exchange, workspace name", doc(writeDeny, tmp), MoveSourceMask | ReplacedMask, "/tmp/evil", RankAllow, "default", 0},
		// A rename allow on /app/** does not make /app/x writable.
		{"rename allow, write deny", doc(writeDeny, Rule{Name: "mv", Action: "allow", Access: []string{AccessRename}, Paths: []string{"/app/**"}}),
			MoveSourceMask, "/app/x", RankDenyEnforce, "default", 1},
		// Review 2 finding 3: a directory moved, linked or exchanged onto a
		// parent written in a write or create deny brings the file with it.
		{"new name guard, rename", doc(allDefaults("allow"), awsConfig), rename | NewFileMask | NewNameGuardMask, "/root/.aws",
			RankDenyEnforce, "d/aws", AccessNewName},
		{"new name guard, replacing rename", doc(allDefaults("allow"), awsConfig), rename | ReplacedMask | NewNameGuardMask, "/root/.aws",
			RankDenyEnforce, "d/aws", AccessNewName},
		// The write deny guards /root/.aws as a move source too.
		{"new name guard, exchange", doc(allDefaults("allow"), awsConfig), MoveSourceMask | ReplacedMask | NewNameGuardMask, "/root/.aws",
			RankDenyEnforce, "d/aws", AccessMoveSource},
		{"new name guard, create-only deny", doc(allDefaults("allow"), Rule{Name: "aws", Action: "deny", Access: []string{AccessCreate},
			Paths: []string{"/root/.aws/config"}}), MoveSourceMask | ReplacedMask | NewNameGuardMask, "/root/.aws",
			RankDenyEnforce, "d/aws", AccessNewName},
		{"new name guard, symbolic link", doc(allDefaults("allow"), awsConfig), create | NewNameGuardMask, "/root/.aws",
			RankDenyEnforce, "d/aws", AccessNewName},
		{"new name guard, mkdir", doc(allDefaults("allow"), awsConfig), create, "/root/.aws", RankAllow, "default", 2},
		{"new name guard, a sibling", doc(allDefaults("allow"), awsConfig), rename | NewFileMask | NewNameGuardMask, "/root/.awsx",
			RankAllow, "default", 1},
		{"no new name guard for a read deny", doc(allDefaults("allow"), awsRead), rename | NewFileMask | NewNameGuardMask, "/root",
			RankAllow, "default", 1},
		// Review 2 finding 4: a new name that does not exist yet is a write.
		{"write-only deny, rename onto a new name", doc(allDefaults("allow"), preload), rename | NewFileMask | NewNameGuardMask,
			"/etc/ld.so.preload", RankDenyEnforce, "d/preload", 1},
		{"write-only deny, hard link onto a new name", doc(allDefaults("allow"), preload), NewFileMask | NewNameGuardMask,
			"/etc/ld.so.preload", RankDenyEnforce, "d/preload", 1},
		{"write-only deny, another new name", doc(allDefaults("allow"), preload), NewFileMask | NewNameGuardMask,
			"/etc/other", RankAllow, "default", 1},
	} {
		c, err := CompileKernel(tc.d, 1)
		if err != nil {
			t.Fatal(err)
		}
		s := newSim(c)
		o, which := s.decideMask(0, tc.mask, s.match(0, tc.path), false)
		if o.rank != tc.rank || c.RuleNames[o.ruleID] != tc.rule || which != tc.which {
			t.Errorf("%s: %s = %d %s access %d, want %d %s access %d", tc.name, tc.path, o.rank, c.RuleNames[o.ruleID], which,
				tc.rank, tc.rule, tc.which)
		}
	}
}

// TestSameAllowRulesMerge: identical allow rules of several documents (the
// owner adds the same built-in rule to each) take one rule of the slot.
func TestSameAllowRulesMerge(t *testing.T) {
	devices := func(name string) Rule {
		return Rule{Name: name, Action: "allow", Access: []string{AccessWrite, AccessRead}, Paths: []string{"/dev/zero", "/dev/null"}}
	}
	fill := func(name string, n int, defaults map[string]Default) Document {
		d := doc(defaults)
		d.Name = name
		for i := 0; i < n; i++ {
			d.Policy.File.Rules = append(d.Policy.File.Rules, Rule{Name: fmt.Sprint(i), Action: "deny", Access: []string{AccessRead},
				Paths: []string{fmt.Sprintf("/%s%d", name, i)}})
		}
		return d
	}
	writeDeny := allDefaults("allow")
	writeDeny[AccessWrite] = Default{Action: "deny"}
	// a: open defaults; b: write default deny (enforce). 32 rules each;
	// together 63 because the device rule merges.
	a := fill("a", 31, allDefaults("allow"))
	a.Policy.File.Rules = append(a.Policy.File.Rules, devices("devices"))
	b := fill("b", 31, writeDeny)
	b.Policy.File.Rules = append([]Rule{devices("devices")}, b.Policy.File.Rules...)
	c, err := CompileSlots([][]Document{{a, b}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Slots[0].NRules; n != 63 {
		t.Fatalf("%d rules, want 63", n)
	}
	// The kept rule is a's (document 0, no default deny). b's enforce write
	// default deny (merge rule 5) must not apply where the allow matches.
	s := newSim(c)
	if got := s.judge(0, AccessWrite, "/dev/null", false); got.rank != RankAllow || c.RuleNames[got.ruleID] != "a/devices" {
		t.Errorf("write /dev/null: rank %d by %s", got.rank, c.RuleNames[got.ruleID])
	}
	if got := s.judge(0, AccessWrite, "/etc/x", false); got.rank != RankDenyEnforce {
		t.Errorf("write /etc/x: rank %d", got.rank)
	}
	// At the limit: one more distinct rule fits, a second does not.
	a.Policy.File.Rules = append(a.Policy.File.Rules, Rule{Name: "x", Action: "deny", Paths: []string{"/x"}})
	if _, err := CompileSlots([][]Document{{a, b}}, 1); err != nil {
		t.Fatalf("64 rules: %v", err)
	}
	b.Policy.File.Rules = append(b.Policy.File.Rules, Rule{Name: "y", Action: "deny", Paths: []string{"/y"}})
	if _, err := CompileSlots([][]Document{{a, b}}, 1); err == nil || !strings.Contains(err.Error(), "rules") {
		t.Fatalf("65 rules: %v", err)
	}
	// Allow rules that differ in access or fromImage stay apart; the same
	// paths in another order are the same rule.
	other := devices("other")
	other.Access = []string{AccessRead}
	img := devices("img")
	img.FromImage = true
	same := Rule{Name: "same", Action: "allow", Access: []string{AccessRead, AccessWrite}, Paths: []string{"/dev/null", "/dev/zero"}}
	c, err = CompileKernel(doc(allDefaults("allow"), devices("devices"), other, img, same), 1)
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Slots[0].NRules; n != 3 {
		t.Errorf("%d rules, want 3", n)
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
		many = append(many, Rule{Name: fmt.Sprint(i), Action: "allow", Paths: []string{fmt.Sprintf("/a%d", i)}})
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
