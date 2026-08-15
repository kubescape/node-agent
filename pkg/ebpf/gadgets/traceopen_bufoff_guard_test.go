package gadgets_test

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

const half = uint32(1 << 14)

func prepend(bufOff uint32, guarded bool) (uint32, bool) {
	if guarded && bufOff < 5 {
		return bufOff, false
	}
	bufOff -= 1
	bufOff -= 4
	return bufOff, true
}

func TestProcPrependOffsetWrap(t *testing.T) {
	for _, off := range []uint32{5, 6, half} {
		got, wrote := prepend(off, false)
		if !wrote || got != off-5 || got > half {
			t.Errorf("buf_off=%d: expected clean in-bounds prepend, got off=%d", off, got)
		}
	}
	for _, off := range []uint32{0, 1, 4} {
		got, wrote := prepend(off, false)
		if wrote && got <= half {
			t.Errorf("buf_off=%d: expected u32 wrap past the half-buffer, got off=%d", off, got)
		}
		if got, wrote = prepend(off, true); wrote || got != off {
			t.Errorf("buf_off=%d: guard must skip the prepend untouched, got off=%d wrote=%v", off, got, wrote)
		}
	}
}

func TestHeaderCarriesGuardAndConstants(t *testing.T) {
	b, err := os.ReadFile("trace_open/filesystem_patched.h")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !regexp.MustCompile(`buf_off >= 5 && BPF_CORE_READ\(dentry, d_sb, s_magic\) == PROC_SUPER_MAGIC`).MatchString(s) {
		t.Error("procfs prepend guard (buf_off >= 5) missing from filesystem_patched.h")
	}
	m := regexp.MustCompile(`MAX_PERCPU_BUFSIZE\s+\(1 << (\d+)\)`).FindStringSubmatch(s)
	if m == nil {
		t.Fatal("MAX_PERCPU_BUFSIZE not found")
	}
	if n, _ := strconv.Atoi(m[1]); uint32(1<<(n-1)) != half {
		t.Errorf("half-buffer mismatch: header 1<<%d/2, test %d", n, half)
	}
	if !regexp.MustCompile(`u32 buf_off = \(MAX_PERCPU_BUFSIZE >> 1\)`).MatchString(s) {
		t.Error("buf_off init changed; wrap analysis assumptions invalid")
	}
}
