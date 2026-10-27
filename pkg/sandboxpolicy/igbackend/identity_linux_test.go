package igbackend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxValidatorRejectsIncompleteAndNonProcIdentity(t *testing.T) {
	_, _, _, b, _ := fixture(t)
	incomplete := b
	incomplete.PID = 0
	if _, err := (LinuxValidator{}).Acquire(context.Background(), incomplete); err == nil {
		t.Fatal("missing PID accepted")
	}
	fakeProc := t.TempDir()
	if err := os.Mkdir(filepath.Join(fakeProc, "123"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := (LinuxValidator{ProcRoot: fakeProc}).Acquire(context.Background(), b); err == nil || !strings.Contains(err.Error(), "procfs") {
		t.Fatalf("non-proc process identity accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (LinuxValidator{}).Acquire(ctx, b); err == nil {
		t.Fatal("canceled acquisition accepted")
	}
}
func TestPinnedProcessStatParsing(t *testing.T) {
	root := t.TempDir()
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	l := &linuxLease{proc: dir}
	defer l.Close()
	// comm can contain spaces and parentheses; starttime must still be field22.
	fields := append([]string{"S"}, make([]string, 19)...)
	for i := 1; i < len(fields); i++ {
		fields[i] = "0"
	}
	fields[19] = "123456"
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("10 (strange ) process) "+strings.Join(fields, " ")), 0600); err != nil {
		t.Fatal(err)
	}
	start, err := l.readStart()
	if err != nil || start != "123456" {
		t.Fatal(start, err)
	}
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.readStart(); err == nil {
		t.Fatal("malformed stat accepted")
	}
}
