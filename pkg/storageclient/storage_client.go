package storageclient

import (
	gcontext "context"
	"fmt"
	"os"
	"sync"
	"time"

	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"sniffer/pkg/context"

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
	retryWatcherSleep                      = 30
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
	storageClient := &StorageK8SAggregatedAPIClient{
		clientset:  clientset,
		readySBOMs: sync.Map{},
	}

	go storageClient.watchForSBOMs()

	return storageClient, nil
}

func (sc *StorageK8SAggregatedAPIClient) watchForSBOMs() {
	for {
		watcher, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Watch(gcontext.TODO(), metav1.ListOptions{})
		if err != nil {
			logger.L().Ctx(context.GetBackgroundContext()).Error("Watch for SBOMs failed ", helpers.Error(err))
			logger.L().Ctx(context.GetBackgroundContext()).Error("Retry in ", helpers.String(fmt.Sprintf("%d", retryWatcherSleep), " seconds"))
			time.Sleep(retryWatcherSleep * time.Second)
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

			SBOM, ok := event.Object.(*spdxv1beta1.SBOMSPDXv2p3)
			if !ok {
				continue
			}

			switch event.Type {
			case watch.Added:
				SBOMmetadataAdded := SBOMMetadata{
					SBOMID:          SBOM.Name,
					SBOMServerState: SBOMServerStateExist,
				}
				sc.readySBOMs.Store(SBOM.Name, SBOMmetadataAdded)
				logger.L().Debug(fmt.Sprintf("new SBOM %s was detected in storage with labels: %v", SBOM.Name, SBOM.Labels))
			case watch.Deleted:
				SBOMmetadataDeleted := SBOMMetadata{
					SBOMID:          SBOM.Name,
					SBOMServerState: SBOMServerStateDeleted,
				}
				sc.readySBOMs.Store(SBOM.Name, SBOMmetadataDeleted)
				logger.L().Debug(fmt.Sprintf("new SBOM %s was deleted from storage with labels: %v", SBOM.Name, SBOM.Labels))
			}
		}

	}
}

func (sc *StorageK8SAggregatedAPIClient) GetData(key string) (any, error) {
	value, exist := sc.readySBOMs.Load(key)
	if !exist {
		return nil, fmt.Errorf("SBOM not exist in server")
	}
	metadata, ok := value.(SBOMMetadata)
	if !ok {
		return nil, fmt.Errorf("failed to convert to SBOM metadata")
	}
	if metadata.SBOMServerState == SBOMServerStateDeleted {
		return nil, fmt.Errorf("SBOM not exist in server, SBOM deleted")
	}
	SBOM, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Get(gcontext.TODO(), key, metav1.GetOptions{})
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
	_, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Update(gcontext.TODO(), SBOM, metav1.UpdateOptions{})
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
	retSBOM, err := sc.clientset.SpdxV1beta1().SBOMSPDXv2p3s(KubescapeNamespace).Create(gcontext.TODO(), SBOM, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	SBOM.ObjectMeta = retSBOM.ObjectMeta
	return nil
}
func IsAlreadyExist(err error) bool {
	return apimachineryerrors.IsAlreadyExists(err)
}
