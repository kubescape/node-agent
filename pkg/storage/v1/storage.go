package storage

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	KubeConfig = "KUBECONFIG"
)

type Storage struct {
	StorageClient spdxv1beta1.SpdxV1beta1Interface
	namespace     string
	multiplier    *int // used for testing to multiply the resources by this
	queueData     *QueueData
}

var _ storage.StorageClient = (*Storage)(nil)

func CreateStorage(ctx context.Context, namespace string, maxElapsedTime time.Duration) (*Storage, error) {
	var cfg *rest.Config
	kubeconfig := os.Getenv(KubeConfig)
	// use the current context in kubeconfig
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
		}
	}
	// force GRPC
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf"
	cfg.ContentType = "application/vnd.kubernetes.protobuf"

	clientset, err := versioned.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
	}

	// wait for storage to be ready
	if err := backoff.RetryNotify(func() error {
		_, err := clientset.SpdxV1beta1().ApplicationProfiles("default").List(context.Background(), metav1.ListOptions{})
		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(5*time.Second), 60), func(err error, d time.Duration) {
		logger.L().Info("waiting for storage to be ready", helpers.Error(err), helpers.String("retry in", d.String()))
	}); err != nil {
		return nil, fmt.Errorf("too many retries waiting for storage: %w", err)
	}

	storage := &Storage{
		StorageClient: clientset.SpdxV1beta1(),
		namespace:     namespace,
		multiplier:    getMultiplier(),
	}

	// Initialize queue
	queueDir := os.Getenv("QUEUE_DIR")
	if queueDir == "" {
		queueDir = DefaultQueueDir
		logger.L().Info("QUEUE_DIR is not set, using default directory", helpers.String("default", DefaultQueueDir))
	}

	// Get max queue size from environment or use default
	maxQueueSize := DefaultMaxQueueSize
	if maxSizeStr := os.Getenv("MAX_QUEUE_SIZE"); maxSizeStr != "" {
		if size, err := strconv.Atoi(maxSizeStr); err == nil && size > 0 {
			maxQueueSize = size
		}
	}

	// Initialize queue with storage as the ProfileCreator
	queueData, err := NewQueueData(ctx, storage, QueueConfig{
		QueueName:       DefaultQueueName,
		QueueDir:        queueDir,
		MaxQueueSize:    maxQueueSize,
		RetryInterval:   DefaultRetryInterval,
		ItemsPerSegment: ItemsPerSegment,
		ErrorCallback:   nil, // Will be set later
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize queue: %w", err)
	}

	storage.queueData = queueData

	// Start queue processing
	storage.queueData.Start()

	logger.L().Info("storage initialized with persistent queue",
		helpers.String("queueDir", queueDir),
		helpers.Int("maxQueueSize", maxQueueSize),
		helpers.Int("currentQueueSize", queueData.GetQueueSize()))

	return storage, nil

}

func CreateFakeStorage(namespace string) (*Storage, error) {
	storage := &Storage{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		namespace:     namespace,
		multiplier:    getMultiplier(),
	}

	// Initialize a simple queue for fake storage (useful for testing)
	queueDir := "/tmp/fake-storage-queue"
	os.MkdirAll(queueDir, 0755)

	queueData, err := NewQueueData(context.Background(), storage, QueueConfig{
		QueueName:       DefaultQueueName + "-fake",
		QueueDir:        queueDir,
		MaxQueueSize:    DefaultMaxQueueSize,
		RetryInterval:   DefaultRetryInterval,
		ItemsPerSegment: ItemsPerSegment,
		ErrorCallback:   nil, // Will be set later if needed
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create fake queue: %w", err)
	}

	storage.queueData = queueData
	storage.queueData.Start()

	return storage, nil
}

func (sc *Storage) CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	return sc.StorageClient.SBOMSyfts(sc.namespace).Create(context.Background(), SBOM, metav1.CreateOptions{})
}

func (sc *Storage) GetSBOMMeta(name string) (*v1beta1.SBOMSyft, error) {
	return sc.StorageClient.SBOMSyfts(sc.namespace).Get(context.Background(), name, metav1.GetOptions{ResourceVersion: softwarecomposition.ResourceVersionMetadata})
}

func (sc *Storage) ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	return sc.StorageClient.SBOMSyfts(sc.namespace).Update(context.Background(), SBOM, metav1.UpdateOptions{})
}

func (sc *Storage) modifyName(n string) string {
	if sc.multiplier != nil {
		return fmt.Sprintf("%s-%d", n, *sc.multiplier)
	}
	return n
}

func (sc *Storage) modifyNameP(n *string) {
	if sc.multiplier != nil {
		*n = fmt.Sprintf("%s-%d", *n, *sc.multiplier)
	}
}

func (sc *Storage) revertNameP(n *string) {
	if sc.multiplier != nil {
		*n = strings.TrimSuffix(*n, fmt.Sprintf("-%d", *sc.multiplier))
	}
}

func getMultiplier() *int {
	if m := os.Getenv("MULTIPLY"); m != "true" {
		return nil
	}
	podName := os.Getenv(config.PodNameEnvVar)
	s := strings.Split(podName, "-")
	if len(s) > 0 {
		if m, err := strconv.Atoi(s[len(s)-1]); err == nil {
			return &m
		}
	}
	return nil
}

// SetErrorCallback sets the error callback for the queue after storage creation
func (sc *Storage) SetErrorCallback(errorCallback storage.ErrorCallback) {
	if sc.queueData != nil {
		sc.queueData.SetErrorCallback(errorCallback)
	}
}
