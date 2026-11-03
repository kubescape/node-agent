// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The gadget folders must move into Inspektor Gadget with only an import-path
// rewrite. So they may import the standard library, Inspektor Gadget (and its
// enforce_exec types), the few libraries Inspektor Gadget itself uses, and each
// other — nothing else from the host repository and no Kubernetes or policy-CRD
// concepts.
var gadgetFolders = []string{"..", "../../enforce_privilege"}

const ownModule = "github.com/kubescape/node-agent/pkg/ebpf/gadgets/"

var allowedImports = []string{
	"github.com/inspektor-gadget/inspektor-gadget/",
	"github.com/cilium/ebpf",
	"github.com/spf13/viper",
	"golang.org/x/sys/",
	"gopkg.in/yaml.v3",
	"oras.land/oras-go/v2", // Inspektor Gadget's OCI store, used by a test
	ownModule + "common/",
	ownModule + "enforce_privilege/",
}

// Names of the host product and its policy API, which the gadgets must not use.
var forbiddenWords = regexp.MustCompile(`(?i)sandbox[ _-]?polic|kubescape\.io|\barmo(sec)?\b|node-agent|kubescape/storage|\bkubernetes\b|\bpods?\b`)

// A BPF include must stay inside the gadget folders: "x.h" or "../common/x.h".
var badInclude = regexp.MustCompile(`#include\s+"(\.\./){2,}|#include\s+"\.\./[^c]`)

func walkGadgetFiles(t *testing.T, fn func(path string, data []byte)) {
	t.Helper()
	for _, root := range gadgetFolders {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "lab" { // lab harness, not part of the gadget
					return filepath.SkipDir
				}
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fn(path, data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestGadgetImportsArePortable(t *testing.T) {
	walkGadgetFiles(t, func(path string, data []byte) {
		if !strings.HasSuffix(path, ".go") {
			return
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				continue // standard library
			}
			ok := false
			for _, allowed := range allowedImports {
				if p == strings.TrimSuffix(allowed, "/") || strings.HasPrefix(p, allowed) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s imports %s, which a portable gadget must not use", path, p)
			}
		}
	})
}

func TestGadgetFilesUseNeutralNames(t *testing.T) {
	walkGadgetFiles(t, func(path string, data []byte) {
		if filepath.Base(path) == "portability_test.go" && filepath.Base(filepath.Dir(path)) == "enforcement" {
			return // this guard lists the forbidden names itself
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, `"`+ownModule) || strings.Contains(trimmed, ` "`+ownModule) ||
				strings.HasPrefix(trimmed, "// Copyright") || strings.HasPrefix(trimmed, "# Copyright") {
				continue // import paths are rewritten on a move; license headers stay
			}
			if badInclude.MatchString(line) {
				t.Errorf("%s:%d includes a header outside the gadget folders", path, i+1)
			}
			if m := forbiddenWords.FindString(line); m != "" {
				t.Errorf("%s:%d uses %q: gadget files must use neutral names", path, i+1, m)
			}
		}
	})
}
