// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The operator publishes the root rotation state in this ConfigMap, in its own
// namespace, under this key. node-agent reads that one object.
const (
	TrustConfigMap = "sandbox-gateway-trust"
	RotationKey    = "rotation.json"
)

// ReadRotation reads the rotation state. A missing ConfigMap or key means no
// rotation is under way.
func ReadRotation(ctx context.Context, client kubernetes.Interface, namespace string) (Rotation, error) {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, TrustConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Rotation{}, nil
	}
	if err != nil {
		return Rotation{}, fmt.Errorf("httpgateway: read %s/%s: %w", namespace, TrustConfigMap, err)
	}
	data, ok := cm.Data[RotationKey]
	if !ok {
		return Rotation{}, nil
	}
	return ParseRotation([]byte(data))
}

// NodeAddresses returns the node's own IP addresses from its status.
func NodeAddresses(node *corev1.Node) []string {
	var out []string
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
			out = append(out, a.Address)
		}
	}
	return out
}
