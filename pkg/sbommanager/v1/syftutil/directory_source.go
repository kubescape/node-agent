package syftutil

import (
	"slices"

	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// HostExclusionPatterns are the Syft exclusion globs applied to every host
// root-filesystem scan.
//
// They cover two distinct concerns:
//
//  1. Container-runtime storage. Without these, a host scan walks every image
//     layer and every container rootfs present on the node, which both explodes
//     the SBOM's size and attributes container packages to the host. The list is
//     deliberately not containerd-only: cri-o/podman store under
//     /var/lib/containers, Docker under /var/lib/docker, and k3s/RKE2 ship an
//     embedded containerd rooted at /var/lib/rancher.
//  2. Pseudo-filesystems (/proc, /sys, /dev). These are not real files; walking
//     them can block indefinitely on device nodes and yields nothing useful.
//
// Syft's directory-source exclusion API (directorysource.GetDirectoryExclusionFunctions)
// requires every pattern to be relative to the scan root and to start with one
// of "./", "*/" or "**/" -- an absolute pattern such as "/var/lib/containerd/**"
// is rejected outright with "invalid exclusion pattern(s)". Hence the "./"
// prefix: these are the host-root-relative spellings of /var/lib/containerd/**,
// /var/lib/docker/**, /run/containerd/**, /proc/**, /sys/** and /dev/**.
var HostExclusionPatterns = []string{
	"./var/lib/containerd/**",
	"./var/lib/docker/**",
	"./var/lib/containers/**",
	"./var/lib/rancher/**",
	"./run/containerd/**",
	"./run/docker/**",
	"./run/crio/**",
	"./proc/**",
	"./sys/**",
	"./dev/**",
}

// NewHostSource builds a Syft directory source rooted at path, for scanning a
// node's root filesystem (as mounted into the agent via HOST_ROOT).
//
// It is deliberately separate from NewSource: that constructor is entirely
// image-driven (it unmarshals a CRI imageStatus, validates layer diff-IDs and
// builds a layer resolver over overlayfs mounts), none of which a host has.
// The resulting source.Description carries source.DirectoryMetadata and
// explicitly no ImageMetadata.
//
// The alias name/version is what Syft uses to derive a stable artifact ID, so
// the ID survives a change of mount point instead of being derived from the
// path.
func NewHostSource(path, name, version string) (source.Source, error) {
	return directorysource.New(directorysource.Config{
		Path: path,
		// GetDirectoryExclusionFunctions rewrites the slice it is given in
		// place (prefixing each entry with the absolute scan root), so the
		// package-level patterns must never be handed over directly.
		Exclude: source.ExcludeConfig{Paths: slices.Clone(HostExclusionPatterns)},
		Alias:   source.Alias{Name: name, Version: version},
	})
}
