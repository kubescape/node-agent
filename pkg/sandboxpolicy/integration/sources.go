package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path"
	"sort"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	profiles "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ProfileResolver struct {
	client spdxv1beta1.ContainerProfilesGetter
}

var _ sandboxpolicy.SourceResolver = (*ProfileResolver)(nil)

func NewProfileResolver(client spdxv1beta1.ContainerProfilesGetter) *ProfileResolver {
	return &ProfileResolver{client: client}
}

// ResolveExecs imports only complete, unambiguous literal-path exec allowlists.
// Exact/anchored argv (including ArgsRequired's explicit-empty semantics), dynamic
// path tokens, and environment constraints cannot be faithfully represented by
// SandboxPolicy's prefix/contains vocabulary: refuse, never widen silently.
// The service must Reconcile on source changes (periodic refresh is sufficient).
func (r *ProfileResolver) ResolveExecs(ctx context.Context, namespace, name, container string) ([]api.ExecRule, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("ContainerProfile client unavailable")
	}
	if namespace == "" || name == "" || container == "" {
		return nil, fmt.Errorf("ContainerProfile namespace/name/container are required")
	}
	profile, err := r.client.ContainerProfiles(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read ContainerProfile %s/%s: %w", namespace, name, err)
	}
	if profile == nil || profile.Namespace != namespace || profile.Name != name || profile.UID == "" {
		return nil, fmt.Errorf("ContainerProfile identity is incomplete or mismatched")
	}
	if profile.Annotations[helpersv1.StatusMetadataKey] != helpersv1.Completed || profile.Annotations[helpersv1.CompletionMetadataKey] != helpersv1.Full {
		return nil, fmt.Errorf("ContainerProfile %s/%s is not completed with full coverage", namespace, name)
	}
	execs, err := profileExecs(profile, container)
	if err != nil {
		return nil, err
	}
	if len(execs) > sandboxpolicy.MaxRulesPerPolicy {
		return nil, fmt.Errorf("ContainerProfile exceeds %d exec entries", sandboxpolicy.MaxRulesPerPolicy)
	}
	paths := make(map[string]bool)
	for _, exec := range execs {
		if exec.ArgsRequired || len(exec.Args) != 0 {
			return nil, fmt.Errorf("ContainerProfile exec %q argv semantics cannot be represented without weakening", exec.Path)
		}
		if len(exec.Envs) != 0 {
			return nil, fmt.Errorf("ContainerProfile exec %q environment constraints are unsupported", exec.Path)
		}
		if exec.Path == "" || !path.IsAbs(exec.Path) || strings.ContainsAny(exec.Path, "*?[]\\\x00") || strings.Contains(exec.Path, "⋯") {
			return nil, fmt.Errorf("ContainerProfile exec path %q is not a supported literal absolute path", exec.Path)
		}
		paths[exec.Path] = true
	}
	ordered := make([]string, 0, len(paths))
	for value := range paths {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	result := make([]api.ExecRule, 0, len(ordered))
	for _, value := range ordered {
		sum := sha256.Sum256([]byte(value))
		result = append(result, api.ExecRule{Rule: api.Rule{Name: fmt.Sprintf("profile-exec-%x", sum[:12]), Action: api.ActionAllow, Origin: "ContainerProfile/" + namespace + "/" + name}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{value}}}})
	}
	return result, nil
}

func profileExecs(profile *profiles.ContainerProfile, container string) ([]profiles.ExecCalls, error) {
	groups := [][]profiles.ContainerProfileContainer{profile.Spec.Containers, profile.Spec.InitContainers, profile.Spec.EphemeralContainers}
	hasGroups := false
	matches := 0
	var selected []profiles.ExecCalls
	for _, group := range groups {
		if len(group) > 0 {
			hasGroups = true
		}
		for _, entry := range group {
			if entry.Name == container {
				matches++
				selected = entry.Execs
			}
		}
	}
	if hasGroups {
		if len(profile.Spec.Execs) != 0 {
			return nil, fmt.Errorf("ContainerProfile mixes top-level and named-container execs")
		}
		if matches != 1 {
			return nil, fmt.Errorf("ContainerProfile must contain exactly one entry for container %q (found %d)", container, matches)
		}
		return selected, nil
	}
	// Agent-learned profiles carry the canonical name label. There is no safe
	// positional or name-prefix inference for selecting a container's execs.
	if profile.Labels[helpersv1.ContainerNameMetadataKey] != container {
		return nil, fmt.Errorf("ContainerProfile container identity does not match %q", container)
	}
	return profile.Spec.Execs, nil
}
