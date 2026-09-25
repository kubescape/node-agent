package hostsensormanager

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func gcTestSensors() []Sensor {
	return supportedHostSensors("test")
}

func TestGCResourcesMatchSupportedSensors(t *testing.T) {
	var want []string
	for _, sensor := range gcTestSensors() {
		want = append(want, sensor.GetPluralKind())
	}
	got := append([]string(nil), hostDataResources...)
	sort.Strings(want)
	sort.Strings(got)
	if len(got) != 10 || !reflect.DeepEqual(got, want) {
		t.Fatalf("GC resources %v differ from canonical sensors %v", got, want)
	}
}

func gcTestClient(t *testing.T, nodes ...string) (*CRDClient, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	kinds := map[schema.GroupVersionResource]string{nodeResource: "NodeList"}
	for _, sensor := range gcTestSensors() {
		kinds[hostDataResource(sensor.GetPluralKind())] = sensor.GetKind() + "List"
	}
	fake := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), kinds)
	for _, name := range nodes {
		gcTestSeed(t, fake, nodeResource, name)
	}
	return &CRDClient{dynamicClient: fake}, fake
}

func gcTestSeed(t *testing.T, fake *dynamicfake.FakeDynamicClient, resource schema.GroupVersionResource, name string) *unstructured.Unstructured {
	t.Helper()
	kind := "Node"
	if resource != nodeResource {
		for _, sensor := range gcTestSensors() {
			if sensor.GetPluralKind() == resource.Resource {
				kind = sensor.GetKind()
			}
		}
	}
	object := &unstructured.Unstructured{}
	object.SetAPIVersion(resource.GroupVersion().String())
	object.SetKind(kind)
	object.SetName(name)
	object.SetUID(types.UID("uid-" + name))
	object.SetResourceVersion("100")
	if err := fake.Tracker().Create(resource, object, ""); err != nil {
		t.Fatal(err)
	}
	return object
}

func gcTestExists(t *testing.T, fake *dynamicfake.FakeDynamicClient, resource schema.GroupVersionResource, name string, want bool) {
	t.Helper()
	_, err := fake.Tracker().Get(resource, "", name)
	if want && err != nil {
		t.Fatalf("expected %s/%s retained: %v", resource.Resource, name, err)
	}
	if !want && !apierrors.IsNotFound(err) {
		t.Fatalf("expected %s/%s deleted: %v", resource.Resource, name, err)
	}
}

func gcTestSweep(t *testing.T, client *CRDClient) {
	t.Helper()
	if err := client.collectHostData(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func gcTestNoDeletes(t *testing.T, fake *dynamicfake.FakeDynamicClient) {
	t.Helper()
	for _, action := range fake.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatalf("unexpected deletion: %#v", action)
		}
	}
}

func TestCollectHostDataNodeDeletionAllKinds(t *testing.T) {
	client, fake := gcTestClient(t, "live", "terminating", "removed")
	node, err := fake.Tracker().Get(nodeResource, "", "terminating")
	if err != nil {
		t.Fatal(err)
	}
	now := metav1.Now()
	node.(*unstructured.Unstructured).SetDeletionTimestamp(&now)
	if err := fake.Tracker().Update(nodeResource, node, ""); err != nil {
		t.Fatal(err)
	}
	for _, resource := range hostDataResources {
		for _, name := range []string{"live", "terminating", "removed"} {
			gcTestSeed(t, fake, hostDataResource(resource), name)
		}
	}
	gcTestSweep(t, client)
	gcTestNoDeletes(t, fake)
	if err := fake.Tracker().Delete(nodeResource, "", "removed"); err != nil {
		t.Fatal(err)
	}
	gcTestSweep(t, client)
	for _, resource := range hostDataResources {
		for _, name := range []string{"live", "terminating", "removed"} {
			gcTestExists(t, fake, hostDataResource(resource), name, name != "removed")
		}
	}
}

func TestCollectHostDataNodeInventoryFailsClosed(t *testing.T) {
	for _, scenario := range []string{"empty", "first page failure", "later page failure"} {
		t.Run(scenario, func(t *testing.T) {
			client, fake := gcTestClient(t)
			gcTestSeed(t, fake, hostDataResource(hostDataResources[0]), "orphan")
			calls := 0
			fake.PrependReactor("list", "nodes", func(action ktesting.Action) (bool, runtime.Object, error) {
				calls++
				if scenario == "empty" {
					return true, &unstructured.UnstructuredList{}, nil
				}
				if scenario == "later page failure" && calls == 1 {
					page := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: map[string]any{"metadata": map[string]any{"name": "live"}}}}}
					page.SetContinue("next")
					return true, page, nil
				}
				return true, nil, errors.New("Node inventory unavailable")
			})
			err := client.collectHostData(context.Background())
			if (err != nil) != (scenario != "empty") {
				t.Fatalf("unexpected error: %v", err)
			}
			gcTestNoDeletes(t, fake)
			for _, action := range fake.Actions() {
				if action.GetResource() != nodeResource {
					t.Fatalf("read host data without a reliable inventory: %#v", action)
				}
			}
		})
	}
}

func TestCollectHostDataPagination(t *testing.T) {
	client, fake := gcTestClient(t)
	resource := hostDataResource(hostDataResources[0])
	live := gcTestSeed(t, fake, resource, "later-page-node")
	orphan := gcTestSeed(t, fake, resource, "orphan")
	nodeCalls, dataCalls := 0, 0
	fake.PrependReactor("list", "nodes", func(action ktesting.Action) (bool, runtime.Object, error) {
		nodeCalls++
		page := &unstructured.UnstructuredList{}
		if nodeCalls == 1 {
			page.SetContinue("node-next")
			page.Items = []unstructured.Unstructured{{Object: map[string]any{"metadata": map[string]any{"name": "first-page-node"}}}}
		} else {
			page.Items = []unstructured.Unstructured{{Object: map[string]any{"metadata": map[string]any{"name": "later-page-node"}}}}
		}
		return true, page, nil
	})
	fake.PrependReactor("list", resource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		dataCalls++
		page := &unstructured.UnstructuredList{}
		if dataCalls == 1 {
			page.Items = []unstructured.Unstructured{*orphan}
			page.SetContinue("data-next")
		} else {
			page.Items = []unstructured.Unstructured{*live}
		}
		return true, page, nil
	})
	gcTestSweep(t, client)
	if nodeCalls != 2 || dataCalls != 2 {
		t.Fatalf("pagination calls nodes=%d hostdata=%d", nodeCalls, dataCalls)
	}
	gcTestExists(t, fake, resource, "later-page-node", true)
	gcTestExists(t, fake, resource, "orphan", false)
}

func TestCollectHostDataIncompleteKindInventory(t *testing.T) {
	client, fake := gcTestClient(t, "live")
	resource := hostDataResource(hostDataResources[0])
	other := hostDataResource(hostDataResources[1])
	orphan := gcTestSeed(t, fake, resource, "orphan")
	gcTestSeed(t, fake, other, "orphan")
	calls := 0
	fake.PrependReactor("list", resource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			page := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*orphan}}
			page.SetContinue("next")
			return true, page, nil
		}
		return true, nil, errors.New("later page failed")
	})
	gcTestSweep(t, client)
	gcTestExists(t, fake, resource, "orphan", true)
	gcTestExists(t, fake, other, "orphan", false)
}

func TestCollectHostDataRechecksNode(t *testing.T) {
	for _, scenario := range []string{"reappeared", "forbidden", "internal", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			client, fake := gcTestClient(t, "live")
			resource := hostDataResource(hostDataResources[0])
			gcTestSeed(t, fake, resource, "candidate")
			fake.PrependReactor("get", "nodes", func(action ktesting.Action) (bool, runtime.Object, error) {
				if action.(ktesting.GetAction).GetName() != "candidate" {
					t.Fatal("unexpected Node recheck")
				}
				switch scenario {
				case "reappeared":
					return true, &unstructured.Unstructured{}, nil
				case "forbidden":
					return true, nil, apierrors.NewForbidden(nodeResource.GroupResource(), "candidate", errors.New("denied"))
				case "internal":
					return true, nil, apierrors.NewInternalError(errors.New("unavailable"))
				default:
					return true, nil, context.DeadlineExceeded
				}
			})
			gcTestSweep(t, client)
			gcTestNoDeletes(t, fake)
			gcTestExists(t, fake, resource, "candidate", true)
		})
	}
}

func TestCollectHostDataKindErrorsAreIsolated(t *testing.T) {
	for _, scenario := range []string{"missing CRD", "forbidden", "internal"} {
		t.Run(scenario, func(t *testing.T) {
			client, fake := gcTestClient(t, "live")
			resource := hostDataResource(hostDataResources[0])
			other := hostDataResource(hostDataResources[1])
			gcTestSeed(t, fake, resource, "orphan")
			gcTestSeed(t, fake, other, "orphan")
			fake.PrependReactor("list", resource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				switch scenario {
				case "missing CRD":
					return true, nil, apierrors.NewNotFound(resource.GroupResource(), "")
				case "forbidden":
					return true, nil, apierrors.NewForbidden(resource.GroupResource(), "", errors.New("denied"))
				default:
					return true, nil, apierrors.NewInternalError(errors.New("unavailable"))
				}
			})
			gcTestSweep(t, client)
			gcTestExists(t, fake, resource, "orphan", true)
			gcTestExists(t, fake, other, "orphan", false)
		})
	}
}

func TestCollectHostDataConditionalDeleteAndRetry(t *testing.T) {
	for _, scenario := range []string{"updated", "recreated", "already deleted", "forbidden"} {
		t.Run(scenario, func(t *testing.T) {
			client, fake := gcTestClient(t, "live")
			resource := hostDataResource(hostDataResources[0])
			object := gcTestSeed(t, fake, resource, "orphan")
			calls := 0
			fake.PrependReactor("delete", resource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				calls++
				preconditions := action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions
				if preconditions == nil || preconditions.UID == nil || preconditions.ResourceVersion == nil {
					t.Fatal("delete must include UID and resourceVersion")
				}
				if *preconditions.UID != object.GetUID() || *preconditions.ResourceVersion != object.GetResourceVersion() {
					t.Fatalf("wrong delete preconditions: %#v", preconditions)
				}
				if calls > 1 {
					return false, nil, nil
				}
				switch scenario {
				case "updated", "recreated":
					object = object.DeepCopy()
					if scenario == "updated" {
						object.SetResourceVersion("101")
					} else {
						object.SetUID("replacement")
						object.SetResourceVersion("200")
					}
					if err := fake.Tracker().Update(resource, object, ""); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewConflict(resource.GroupResource(), "orphan", errors.New("precondition failed"))
				case "already deleted":
					if err := fake.Tracker().Delete(resource, "", "orphan"); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewNotFound(resource.GroupResource(), "orphan")
				default:
					return true, nil, apierrors.NewForbidden(resource.GroupResource(), "orphan", errors.New("denied"))
				}
			})
			gcTestSweep(t, client)
			gcTestExists(t, fake, resource, "orphan", scenario != "already deleted")
			gcTestSweep(t, client)
			gcTestExists(t, fake, resource, "orphan", false)
			wantCalls := 2
			if scenario == "already deleted" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("delete calls %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestCollectHostDataRejectsMissingPreconditions(t *testing.T) {
	for _, missing := range []string{"UID", "resourceVersion"} {
		t.Run(missing, func(t *testing.T) {
			client, fake := gcTestClient(t, "live")
			resource := hostDataResource(hostDataResources[0])
			object := gcTestSeed(t, fake, resource, "orphan")
			if missing == "UID" {
				object.SetUID("")
			} else {
				object.SetResourceVersion("")
			}
			if err := fake.Tracker().Update(resource, object, ""); err != nil {
				t.Fatal(err)
			}
			gcTestSweep(t, client)
			gcTestNoDeletes(t, fake)
		})
	}
}

// The dynamic fake discards pagination options, so exercise their transmission
// through a ResourceInterface implementation rather than trusting fake actions.
type gcTestListResource struct {
	dynamic.ResourceInterface
	list func(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (r gcTestListResource) List(ctx context.Context, options metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return r.list(ctx, options)
}

func TestListGCObjectsPaginationOptionsAndTimeout(t *testing.T) {
	calls := 0
	var previous context.Context
	resource := gcTestListResource{list: func(ctx context.Context, options metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		if ctx.Err() != nil {
			t.Fatalf("request context is already cancelled: %v", ctx.Err())
		}
		if previous != nil && previous.Err() != context.Canceled {
			t.Fatal("previous page request was not released")
		}
		previous = ctx
		if options.Limit != 500 || options.LabelSelector != "" || options.FieldSelector != "" {
			t.Fatalf("unexpected list options: %#v", options)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("API operation has no deadline")
		}
		page := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{}}}
		if calls == 1 {
			if options.Continue != "" {
				t.Fatal("unexpected initial continuation")
			}
			page.SetContinue("next")
		} else {
			if options.Continue != "next" {
				t.Fatal("missing continuation")
			}
		}
		return page, nil
	}}
	objects, err := listGCObjects(context.Background(), resource)
	if err != nil || len(objects) != 2 || calls != 2 {
		t.Fatalf("objects=%d calls=%d err=%v", len(objects), calls, err)
	}
}

func TestCollectHostDataRecoversAfterNodeListFailure(t *testing.T) {
	client, fake := gcTestClient(t, "live")
	resource := hostDataResource(hostDataResources[0])
	gcTestSeed(t, fake, resource, "orphan")
	failed := false
	fake.PrependReactor("list", "nodes", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !failed {
			failed = true
			return true, nil, apierrors.NewInternalError(errors.New("temporary failure"))
		}
		return false, nil, nil
	})
	if err := client.collectHostData(context.Background()); err == nil {
		t.Fatal("expected inventory error")
	}
	gcTestNoDeletes(t, fake)
	gcTestExists(t, fake, resource, "orphan", true)
	gcTestSweep(t, client)
	gcTestExists(t, fake, resource, "orphan", false)
}
