package storageclient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

const (
	KubeConfig                             = "KUBECONFIG"
	KubescapeNamespace                     = "kubescape"
	SBOMServerStateExist   SBOMServerState = "Exist"
	SBOMServerStateDeleted SBOMServerState = "Deleted"
	retryWatcherSleep                      = 5
)

type SBOMServerState string

type SBOMMetadata struct {
	SBOMID string
	SBOMServerState
}

type StorageK8SAggregatedAPIClient struct {
	clientset  *spdxclient.Clientset
	readySBOMs sync.Map
}

var _ StorageClient = (*StorageK8SAggregatedAPIClient)(nil)

func CreateSBOMStorageK8SAggregatedAPIClient(ctx context.Context) (*StorageK8SAggregatedAPIClient, error) {
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
	storageClient := &StorageK8SAggregatedAPIClient{
		clientset:  clientset,
		readySBOMs: sync.Map{},
	}

	go storageClient.watchForSBOMs(ctx)

	return storageClient, nil
}

func (sc *StorageK8SAggregatedAPIClient) watchForSBOMs(ctx context.Context) {
	for {
		watcher, err := sc.clientset.SpdxV1beta1().SBOMSummaries(KubescapeNamespace).Watch(context.TODO(), metav1.ListOptions{})
		if err != nil {
			logger.L().Error("Watch for SBOMs failed", helpers.Error(err))
			continue
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			if !chanActive {
				watcher.Stop()
				break
			}
			if event.Type == watch.Error {
				watcher.Stop()
				break
			}

			SBOM, ok := event.Object.(*spdxv1beta1.SBOMSummary)
			if !ok {
				continue
			}

			switch event.Type {
			case watch.Added:
				SBOMetadataAdded := SBOMMetadata{
					SBOMID:          SBOM.Name,
					SBOMServerState: SBOMServerStateExist,
				}
				sc.readySBOMs.Store(SBOM.Name, SBOMetadataAdded)
				logger.L().Debug(fmt.Sprintf("new SBOM %s was detected in storage with labels: %v", SBOM.Name, SBOM.Labels))
			case watch.Deleted:
				SBOMetadataDeleted := SBOMMetadata{
					SBOMID:          SBOM.Name,
					SBOMServerState: SBOMServerStateDeleted,
				}
				sc.readySBOMs.Store(SBOM.Name, SBOMetadataDeleted)
				logger.L().Debug(fmt.Sprintf("new SBOM %s was deleted from storage with labels: %v", SBOM.Name, SBOM.Labels))
			}
		}
	}
}

func (sc *StorageK8SAggregatedAPIClient) GetData(ctx context.Context, key string) (any, error) {
	// _, span := otel.Tracer("").Start(ctx, "StorageK8SAggregatedAPIClient.GetData")
	// defer span.End()

	SBOM, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Get(context.TODO(), key, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// remove fields that are not needed
	SBOM.ResourceVersion = ""
	SBOM.CreationTimestamp = metav1.Time{}
	SBOM.Generation = 0
	SBOM.UID = ""

	return SBOM, nil
}

func (sc *StorageK8SAggregatedAPIClient) PutData(ctx context.Context, key string, data any) error {
	// _, span := otel.Tracer("").Start(ctx, "StorageK8SAggregatedAPIClient.PutData")
	// defer span.End()
	SBOM, ok := data.(*spdxv1beta1.SBOMSPDXv2p3Filtered)
	if !ok {
		return fmt.Errorf("failed to update SBOM: SBOM is not in the right form")
	}
	bytes, err := json.Marshal(SBOM)
	if err != nil {
		return err
	}
	_, err = sc.clientset.SpdxV1beta1().SBOMSPDXv2p3Filtereds(KubescapeNamespace).Patch(context.TODO(), key, types.StrategicMergePatchType, bytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc *StorageK8SAggregatedAPIClient) PostData(ctx context.Context, data any) error {
	// _, span := otel.Tracer("").Start(ctx, "StorageK8SAggregatedAPIClient.PostData")
	// defer span.End()
	SBOM, ok := data.(*spdxv1beta1.SBOMSPDXv2p3Filtered)
	if !ok {
		return fmt.Errorf("failed to update SBOM: SBOM is not in the right form")
	}
	_, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3Filtereds(KubescapeNamespace).Create(context.TODO(), SBOM, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func IsAlreadyExist(err error) bool {
	return apimachineryerrors.IsAlreadyExists(err)
}
