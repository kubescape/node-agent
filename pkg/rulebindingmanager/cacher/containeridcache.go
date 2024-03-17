package cacher

import (
	corev1 "k8s.io/api/core/v1"
)

type containerEntry struct {
	ContainerID   string
	ContainerName string
	PodName       string
	Namespace     string
	OwnerKind     string
	OwnerName     string
	// Low level container information
	NsMntId uint64

	// Attached late (after container already started)
	AttachedLate bool

	// Pod spec
	PodSpec *corev1.PodSpec

	// Add rules here
	// BoundRules []rule.Rule
}
