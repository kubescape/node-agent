package storageclient

import (
	"context"
	"fmt"
	"os"

	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

const (
	KubeConfig         = "KUBECONFIG"
	KubescapeNamespace = "kubescape"
)

type StorageK8SAggregatedAPIClient struct {
	clientset *spdxclient.Clientset
}

var storageclientErrors map[string]error

func init() {
	storageclientErrors = map[string]error{}
}

func CreateSBOMStorageK8SAggregatedAPIClient() (*StorageK8SAggregatedAPIClient, error) {
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

	clientset, err := spdxclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
	}
	return &StorageK8SAggregatedAPIClient{
		clientset: clientset,
	}, nil
}

func (sc *StorageK8SAggregatedAPIClient) GetData(key string) (any, error) {
	SBOM, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Get(context.TODO(), key, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return SBOM, nil
}
func (sc *StorageK8SAggregatedAPIClient) PutData(key string, data any) error {
	SBOM, ok := data.(*spdxv1beta1.SBOMSPDXv2p3)
	if !ok {
		return fmt.Errorf("failed to update SBOM: SBOM is not in the right form")
	}
	_, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Update(context.TODO(), SBOM, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}
func (sc *StorageK8SAggregatedAPIClient) PostData(key string, data any) error {
	SBOM, ok := data.(*spdxv1beta1.SBOMSPDXv2p3)
	if !ok {
		return fmt.Errorf("failed to update SBOM: SBOM is not in the right form")
	}
	_, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Create(context.TODO(), SBOM, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
func IsAlreadyExist(err error) bool {
	return apimachineryerrors.IsAlreadyExists(err)
}
