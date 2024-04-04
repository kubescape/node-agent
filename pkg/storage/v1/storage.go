package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"os"
	"strconv"

	iidhelpers "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	DefaultMaxApplicationProfileSize = 10000
	KubeConfig                       = "KUBECONFIG"
)

type Storage struct {
	StorageClient             spdxv1beta1.SpdxV1beta1Interface
	maxApplicationProfileSize int
	namespace                 string
}

var _ storage.StorageClient = (*Storage)(nil)

func CreateStorage(namespace string) (*Storage, error) {
	var config *rest.Config
	kubeconfig := os.Getenv(KubeConfig)
	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
		}
	}

	clientset, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
	}

	maxApplicationProfileSize, err := strconv.Atoi(os.Getenv("MAX_APPLICATION_PROFILE_SIZE"))
	if err != nil {
		maxApplicationProfileSize = DefaultMaxApplicationProfileSize
	}

	return &Storage{
		StorageClient:             clientset.SpdxV1beta1(),
		maxApplicationProfileSize: maxApplicationProfileSize,
		namespace:                 namespace,
	}, nil
}

func CreateFakeStorage(namespace string) (*Storage, error) {
	return &Storage{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		namespace:     namespace,
	}, nil
}

func (sc Storage) CreateNetworkNeighbors(networkNeighbors *v1beta1.NetworkNeighbors, namespace string) error {
	_, err := sc.StorageClient.NetworkNeighborses(namespace).Create(context.Background(), networkNeighbors, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) GetNetworkNeighbors(namespace, name string) (*v1beta1.NetworkNeighbors, error) {
	return sc.StorageClient.NetworkNeighborses(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc Storage) PatchNetworkNeighborsIngressAndEgress(name, namespace string, networkNeighbors *v1beta1.NetworkNeighbors) error {
	bytes, err := json.Marshal(networkNeighbors)
	if err != nil {
		return err
	}

	_, err = sc.StorageClient.NetworkNeighborses(namespace).Patch(context.Background(), name, types.StrategicMergePatchType, bytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (sc Storage) PatchNetworkNeighborsMatchLabels(name, namespace string, networkNeighbors *v1beta1.NetworkNeighbors) error {
	_, err := sc.StorageClient.NetworkNeighborses(namespace).Update(context.Background(), networkNeighbors, metav1.UpdateOptions{})

	return err
}

func (sc Storage) CreateApplicationActivity(activity *v1beta1.ApplicationActivity, namespace string) error {
	_, err := sc.StorageClient.ApplicationActivities(namespace).Create(context.Background(), activity, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) GetApplicationActivity(namespace, name string) (*v1beta1.ApplicationActivity, error) {
	return sc.StorageClient.ApplicationActivities(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc Storage) CreateApplicationProfile(profile *v1beta1.ApplicationProfile, namespace string) error {
	// unset resourceVersion
	profile.ResourceVersion = ""
	_, err := sc.StorageClient.ApplicationProfiles(namespace).Create(context.Background(), profile, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) PatchApplicationProfile(name, namespace string, patch []byte, channel chan error) error {
	profile, err := sc.StorageClient.ApplicationProfiles(namespace).Patch(context.Background(), name, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch application profile: %w", err)
	}
	// check if returned profile is full
	if s, ok := profile.Annotations[iidhelpers.StatusMetadataKey]; ok {
		if s == iidhelpers.TooLarge {
			if channel != nil {
				channel <- utils.TooLargeApplicationProfileError
			}
		}
		return nil
	}
	// check if returned profile is too big
	if s, ok := profile.Annotations[iidhelpers.ResourceSizeMetadataKey]; ok {
		size, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("parse size: %w", err)
		}
		if size > sc.maxApplicationProfileSize {
			// add annotation to indicate that the profile is full
			annotationOperations := []utils.PatchOperation{
				{
					Op:    "replace",
					Path:  "/metadata/annotations/" + utils.EscapeJSONPointerElement(iidhelpers.StatusMetadataKey),
					Value: iidhelpers.TooLarge,
				},
			}
			annotationsPatch, err := json.Marshal(annotationOperations)
			if err != nil {
				return fmt.Errorf("create patch for annotations: %w", err)
			}
			_, err = sc.StorageClient.ApplicationProfiles(namespace).Patch(context.Background(), name, types.JSONPatchType, annotationsPatch, metav1.PatchOptions{})
			if err != nil {
				return fmt.Errorf("patch application profile annotations: %w", err)
			}
			if channel != nil {
				channel <- utils.TooLargeApplicationProfileError
			}
		}
	}
	return nil
}

func (sc Storage) GetApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error) {
	return sc.StorageClient.ApplicationProfiles(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc Storage) CreateFilteredSBOM(SBOM *v1beta1.SBOMSyftFiltered) error {
	_, err := sc.StorageClient.SBOMSyftFiltereds(sc.namespace).Create(context.Background(), SBOM, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) GetFilteredSBOM(name string) (*v1beta1.SBOMSyftFiltered, error) {
	return sc.StorageClient.SBOMSyftFiltereds(sc.namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc Storage) GetSBOM(name string) (*v1beta1.SBOMSyft, error) {
	return sc.StorageClient.SBOMSyfts(sc.namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc Storage) PatchFilteredSBOM(name string, SBOM *v1beta1.SBOMSyftFiltered) error {
	bytes, err := json.Marshal(SBOM)
	if err != nil {
		return err
	}
	_, err = sc.StorageClient.SBOMSyftFiltereds(sc.namespace).Patch(context.Background(), name, types.StrategicMergePatchType, bytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) IncrementImageUse(_ string) {
	// noop
}

func (sc Storage) DecrementImageUse(_ string) {
	// noop
}
