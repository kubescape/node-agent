package networkstream

import (
	"context"
	"fmt"
	"strings"

	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// getTopOwnerReference finds the highest-level owner of a pod
func (ns *NetworkStream) getTopOwnerReference(namespace, podName string, initialOwnerReferences []metav1.OwnerReference) (*metav1.OwnerReference, error) {
	resGroupVersion := "v1"
	resKind := "pods"
	resName := podName
	resNamespace := namespace

	var highestOwnerRef *metav1.OwnerReference
	ownerReferences := initialOwnerReferences

	// Iterate until we reach the highest level of reference
	for {
		if len(ownerReferences) == 0 {
			var err error
			ownerReferences, err = ns.getOwnerReferences(
				resNamespace, resKind, resGroupVersion, resName)
			if err != nil {
				return nil, fmt.Errorf("getting %s/%s/%s/%s owner reference: %w",
					resNamespace, resKind, resGroupVersion, resName, err)
			}

			// No owner reference found
			if len(ownerReferences) == 0 {
				break
			}
		}

		ownerRef := ns.getExpectedOwnerReference(ownerReferences)
		if ownerRef == nil {
			// No expected owner reference found
			break
		}

		// Update parameters for next iteration (Namespace does not change)
		highestOwnerRef = ownerRef
		resGroupVersion = ownerRef.APIVersion
		resKind = strings.ToLower(ownerRef.Kind) + "s"
		resName = ownerRef.Name
		ownerReferences = nil
	}

	return highestOwnerRef, nil
}

// getOwnerReferences gets the owner references for a resource
func (ns *NetworkStream) getOwnerReferences(namespace, kind, groupVersion, name string) ([]metav1.OwnerReference, error) {
	gv := strings.Split(groupVersion, "/")
	group := ""
	version := groupVersion

	if len(gv) == 2 {
		group = gv[0]
		version = gv[1]
	}

	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: kind,
	}

	obj, err := ns.k8sClient.GetDynamicClient().Resource(gvr).Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	metadata, ok := obj.Object["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("metadata not found or not a map")
	}

	ownerRefsI, ok := metadata["ownerReferences"]
	if !ok {
		return nil, nil // No owner references
	}

	ownerRefsArr, ok := ownerRefsI.([]interface{})
	if !ok {
		return nil, fmt.Errorf("ownerReferences not an array")
	}

	var result []metav1.OwnerReference
	for _, ownerRefI := range ownerRefsArr {
		ownerRefMap, ok := ownerRefI.(map[string]interface{})
		if !ok {
			continue
		}

		apiVersion, _ := ownerRefMap["apiVersion"].(string)
		kind, _ := ownerRefMap["kind"].(string)
		name, _ := ownerRefMap["name"].(string)
		uid, _ := ownerRefMap["uid"].(string)
		controller, hasController := ownerRefMap["controller"].(bool)

		ownerRef := metav1.OwnerReference{
			APIVersion: apiVersion,
			Kind:       kind,
			Name:       name,
			UID:        types.UID(uid),
		}

		if hasController {
			ownerRef.Controller = &controller
		}

		result = append(result, ownerRef)
	}

	return result, nil
}

// getExpectedOwnerReference returns a resource only if it has an expected kind.
// In the case of multiple references, it first tries to find the controller
// reference. If there does not exist or it does not have an expected kind, the
// function will try to find the first resource with one of the expected
// resource kinds. Otherwise, it returns nil.
func (ns *NetworkStream) getExpectedOwnerReference(ownerReferences []metav1.OwnerReference) *metav1.OwnerReference {
	// From: https://kubernetes.io/docs/concepts/workloads/controllers/
	// Notice that any change on this map needs to be aligned with the gadget
	// cluster role.
	expectedResKinds := map[string]struct{}{
		"Deployment":            {},
		"ReplicaSet":            {},
		"StatefulSet":           {},
		"DaemonSet":             {},
		"Job":                   {},
		"CronJob":               {},
		"ReplicationController": {},
	}

	var ownerRef *metav1.OwnerReference
	for i, or := range ownerReferences {
		if _, ok := expectedResKinds[or.Kind]; !ok {
			continue
		}
		if or.Controller != nil && *or.Controller {
			// There is at most one controller reference per resource
			return &or
		}
		// Keep track of the first expected reference in case it will be needed
		if ownerRef == nil {
			ownerRef = &ownerReferences[i]
		}
	}

	return ownerRef
}

func getNetworkEndpointIdentifier(event *tracernetworktype.Event) string {
	return fmt.Sprintf("%s/%d/%s", event.DstEndpoint.Addr, event.Port, event.Proto)
}
