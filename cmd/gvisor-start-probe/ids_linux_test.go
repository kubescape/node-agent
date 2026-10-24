//go:build linux

package main

import (
	"flag"
	"strings"
	"testing"
)

func TestContainerIDsExactMatching(t *testing.T) {
	var ids containerIDs
	flags := flag.NewFlagSet("trial", flag.ContinueOnError)
	flags.Var(&ids, "container-id", "runtime identity")
	if err := flags.Parse([]string{"--container-id", "sandbox-a", "--container-id", "sandbox-b", "--container-id", "sandbox-a"}); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}
	for _, id := range []string{"sandbox-a", "sandbox-b"} {
		if !ids.resolves(id) {
			t.Fatal("known ID rejected")
		}
	}
	for _, id := range []string{"", "sandbox", "sandbox-a-suffix", "unknown"} {
		if ids.resolves(id) {
			t.Fatal("unverified ID accepted")
		}
	}
}

func TestContainerIDsRejectInvalidValues(t *testing.T) {
	var ids containerIDs
	for _, id := range []string{"", "with space", "with\nnewline", strings.Repeat("a", 257)} {
		if err := ids.Set(id); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if len(ids) != 0 {
		t.Fatal("invalid IDs changed allowlist")
	}
	if err := ids.Set(strings.Repeat("a", 256)); err != nil {
		t.Fatal(err)
	}
}
