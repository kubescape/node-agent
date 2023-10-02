package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"node-agent/pkg/storage"
	"os"

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
	KubeConfig       = "KUBECONFIG"
	defaultNamespace = "kubescape"
)

type StorageNoCache struct {
	StorageClient spdxv1beta1.SpdxV1beta1Interface
	namespace     string
}

var _ storage.StorageClient = (*StorageNoCache)(nil)

func CreateStorageNoCache() (*StorageNoCache, error) {
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

	return &StorageNoCache{
		StorageClient: clientset.SpdxV1beta1(),
		namespace:     getNamespace(),
	}, nil
}

func CreateFakeStorageNoCache() (*StorageNoCache, error) {
	return &StorageNoCache{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		namespace:     getNamespace(),
	}, nil
}

func getNamespace() string {
	if ns, ok := os.LookupEnv("NAMESPACE"); ok {
		return ns
	}
	return defaultNamespace
}

func (sc StorageNoCache) CreateApplicationActivity(activity *v1beta1.ApplicationActivity, namespace string) error {
	_, err := sc.StorageClient.ApplicationActivities(namespace).Create(context.Background(), activity, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc StorageNoCache) CreateApplicationProfile(profile *v1beta1.ApplicationProfile, namespace string) error {
	_, err := sc.StorageClient.ApplicationProfiles(namespace).Create(context.Background(), profile, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc StorageNoCache) CreateApplicationProfileSummary(profile *v1beta1.ApplicationProfileSummary, namespace string) error {
	_, err := sc.StorageClient.ApplicationProfileSummaries(namespace).Create(context.Background(), profile, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc StorageNoCache) CreateFilteredSBOM(SBOM *v1beta1.SBOMSPDXv2p3Filtered) error {
	_, err := sc.StorageClient.SBOMSPDXv2p3Filtereds(sc.namespace).Create(context.Background(), SBOM, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc StorageNoCache) GetSBOM(name string) (*v1beta1.SBOMSPDXv2p3, error) {
	SBOM, err := sc.StorageClient.SBOMSPDXv2p3s(sc.namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return SBOM, nil
}

func (sc StorageNoCache) PatchFilteredSBOM(name string, SBOM *v1beta1.SBOMSPDXv2p3Filtered) error {
	bytes, err := json.Marshal(SBOM)
	if err != nil {
		return err
	}
	_, err = sc.StorageClient.SBOMSPDXv2p3Filtereds(sc.namespace).Patch(context.Background(), name, types.StrategicMergePatchType, bytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc StorageNoCache) IncrementImageUse(_ string) {
	// noop
}

func (sc StorageNoCache) DecrementImageUse(_ string) {
	// noop
}