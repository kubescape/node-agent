package containerprofilecache_integration

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestLegacyPackagesDeleted — T5.
//
// Walks the full dependency graph of ./... and asserts that neither of the
// deleted legacy cache packages appears as a reachable import path. Any
// surviving importer is listed in the failure message.
func TestLegacyPackagesDeleted(t *testing.T) {
	const (
		legacyAP = "github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache"
		legacyNN = "github.com/kubescape/node-agent/pkg/objectcache/networkneighborhoodcache"
	)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedImports | packages.NeedDeps,
		// Load from the module root so that ./... expands correctly.
		Dir: "../..",
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load failed: %v", err)
	}

	// Collect errors from the package loader (missing modules, parse errors, …).
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Msg)
		}
	})
	if len(loadErrs) > 0 {
		// Non-fatal: the loader often emits spurious CGO / build-tag errors on
		// CI. We only fail if we can't inspect any packages at all.
		t.Logf("packages.Load reported %d non-fatal errors (first: %s)", len(loadErrs), loadErrs[0])
	}

	if len(pkgs) == 0 {
		t.Fatal("packages.Load returned no packages — cannot verify legacy-path absence")
	}

	// Build import-path → importing package map for the two legacy paths.
	importers := map[string][]string{
		legacyAP: {},
		legacyNN: {},
	}

	packages.Visit(pkgs, func(p *packages.Package) bool {
		for importPath := range p.Imports {
			if importPath == legacyAP {
				importers[legacyAP] = append(importers[legacyAP], p.PkgPath)
			}
			if importPath == legacyNN {
				importers[legacyNN] = append(importers[legacyNN], p.PkgPath)
			}
		}
		return true
	}, nil)

	for legacy, importerList := range importers {
		if len(importerList) > 0 {
			t.Errorf("legacy package %q is still imported by:\n  %s",
				legacy, strings.Join(importerList, "\n  "))
		}
	}
}
