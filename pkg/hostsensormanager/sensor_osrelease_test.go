package hostsensormanager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetOsReleaseFileIgnoresDecoyReleaseFiles(t *testing.T) {
	tmp := t.TempDir()
	etcDir := filepath.Join(tmp, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// centos-release ends with "os-release" as a substring but is a different,
	// differently-formatted file. It must not be picked over the real one.
	for _, name := range []string{"centos-release", "os-release"} {
		if err := os.WriteFile(filepath.Join(etcDir, name), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origPrefix := hostFSPrefix
	hostFSPrefix = tmp
	defer func() { hostFSPrefix = origPrefix }()

	s := &OsReleaseSensor{}
	got, err := s.getOsReleaseFile()
	if err != nil {
		t.Fatalf("getOsReleaseFile() error = %v", err)
	}
	if got != "os-release" {
		t.Errorf("getOsReleaseFile() = %q, want %q", got, "os-release")
	}
}

func TestGetOsReleaseFileNotFoundAmongDecoysOnly(t *testing.T) {
	tmp := t.TempDir()
	etcDir := filepath.Join(tmp, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etcDir, "centos-release"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	origPrefix := hostFSPrefix
	hostFSPrefix = tmp
	defer func() { hostFSPrefix = origPrefix }()

	s := &OsReleaseSensor{}
	if _, err := s.getOsReleaseFile(); err == nil {
		t.Error("getOsReleaseFile() expected an error when only a decoy file is present, got nil")
	}
}
