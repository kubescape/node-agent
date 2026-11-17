//go:build !sandbox_shared_qualification

// Command check-product-images checks the enforce_exec shared product images
// in a built tracers.tar against the agent's compiled-in kernel table
// (integration.VerifyCompiledInImages): every compiled-in image must resolve
// in the archive to its pinned amd64 manifest digest.
//
// Usage: check-product-images [TRACERS_TAR]   (default tracers.tar)
package main

import (
	"context"
	"fmt"
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
	store, err := orasoci.NewFromTar(ctx, archive)
	if err == nil {
		err = integration.VerifyCompiledInImages(ctx, store)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-product-images: %s: %v\n", archive, err)
		os.Exit(1)
	}
	fmt.Printf("check-product-images: %s: every compiled-in product image matches its pinned manifest digest\n", archive)
}
