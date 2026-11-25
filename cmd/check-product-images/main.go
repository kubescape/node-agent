//go:build !sandbox_shared_qualification

// Command check-product-images checks the exec and section product images
// in a built tracers.tar against the agent's compiled-in pins
// (integration.VerifyCompiledInImages): each must resolve in the archive to its
// pinned manifest digest for amd64, and every blob that manifest references
// must be present and digest-verified.
//
// Usage: check-product-images [TRACERS_TAR]   (default tracers.tar)
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy/integration"
	orasoci "oras.land/oras-go/v2/content/oci"
)

func main() {
	archive := "tracers.tar"
	switch len(os.Args) {
	case 1:
	case 2:
		archive = os.Args[1]
	default:
		fmt.Fprintln(os.Stderr, "usage: check-product-images [TRACERS_TAR]")
		os.Exit(2)
	}
	ctx := context.Background()
	if _, err := os.Stat(archive); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "check-product-images: %s does not exist; run `make gadgets` first\n", archive)
		os.Exit(1)
	}
	store, err := orasoci.NewFromTar(ctx, archive)
	if err == nil {
		err = integration.VerifyCompiledInImages(ctx, store)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-product-images: %s: %v\n", archive, err)
		os.Exit(1)
	}
	fmt.Printf("check-product-images: %s: all enforcement images match their pinned manifest digests and their blobs verify\n", archive)
}
