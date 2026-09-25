package hostsensormanager

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const gcRequestTimeout = 30 * time.Second

// Include every supported type, even when its sensor is disabled or fails.
var hostDataResources = []string{
	"osreleasefiles", "kernelversions", "linuxsecurityhardeningstatuses",
	"openportslists", "linuxkernelvariables", "kubeletinfos", "kubeproxyinfos",
	"controlplaneinfos", "cloudproviderinfos", "cniinfos",
}

var nodeResource = schema.GroupVersionResource{Version: "v1", Resource: "nodes"}

func hostDataResource(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: HostDataGroup, Version: HostDataVersion, Resource: resource}
}

// listGCObjects never returns a partial inventory. Each page has its own deadline.
func listGCObjects(ctx context.Context, client dynamic.ResourceInterface) ([]unstructured.Unstructured, error) {
	var objects []unstructured.Unstructured
	options := metav1.ListOptions{Limit: 500}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		requestCtx, cancel := context.WithTimeout(ctx, gcRequestTimeout)
		page, err := client.List(requestCtx, options)
		cancel()
		if err != nil {
			return nil, err
		}
		objects = append(objects, page.Items...)
		options.Continue = page.GetContinue()
		if options.Continue == "" {
			return objects, nil
		}
	}
}

// collectHostData only deletes after both a complete Node inventory and a fresh
// Node lookup establish absence. Kubernetes cannot make that lookup and the
// subsequent deletion of a different resource atomic.
func (c *CRDClient) collectHostData(ctx context.Context) error {
	nodes, err := listGCObjects(ctx, c.dynamicClient.Resource(nodeResource))
	if err != nil {
		return fmt.Errorf("list Nodes for host-data cleanup: %w", err)
	}
	if len(nodes) == 0 {
		return nil
	}
	present := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		present[node.GetName()] = struct{}{}
	}
	for _, resource := range hostDataResources {
		if err := ctx.Err(); err != nil {
			return err
		}
		client := c.dynamicClient.Resource(hostDataResource(resource))
		objects, err := listGCObjects(ctx, client)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				logGCError(resource, "", err)
			}
			continue
		}
		for _, object := range objects {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := object.GetName()
			if _, exists := present[name]; exists {
				continue
			}
			requestCtx, cancel := context.WithTimeout(ctx, gcRequestTimeout)
			_, err := c.dynamicClient.Resource(nodeResource).Get(requestCtx, name, metav1.GetOptions{})
			cancel()
			if err == nil {
				continue
			}
			if !apierrors.IsNotFound(err) {
				logGCError(resource, name, err)
				continue
			}
			// Never issue an unconditional delete, including on malformed API responses.
			uid, version := object.GetUID(), object.GetResourceVersion()
			if uid == "" || version == "" {
				logGCError(resource, name, fmt.Errorf("missing UID or resourceVersion"))
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			requestCtx, cancel = context.WithTimeout(ctx, gcRequestTimeout)
			err = client.Delete(requestCtx, name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version},
			})
			cancel()
			if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
				logGCError(resource, name, err)
			}
		}
	}
	return ctx.Err()
}

func logGCError(resource, name string, err error) {
	logger.L().Warning("host-data cleanup failed; will retry", helpers.String("resource", resource), helpers.String("name", name), helpers.Error(err))
}
