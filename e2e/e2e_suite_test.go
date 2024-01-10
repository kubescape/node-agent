package e2e

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	cfg       *rest.Config
	k8sClient *kubernetes.Clientset
	testEnv   *envtest.Environment
)

func TestE2e(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "node-agent e2e-tests")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter)))

	By("bootstrapping test environment")

	// connecting to existing Kubernetes cluster
	clusterExists := true
	testEnv = &envtest.Environment{
		UseExistingCluster: &clusterExists,
	}

	cfg, err := testEnv.Start()
	Expect(err).To(BeNil())

	Expect(err).To(BeNil())
	k8sClient, err = kubernetes.NewForConfig(cfg)
	Expect(err).To(BeNil())

	// wait until all the needed pods are in Running state
	label := fmt.Sprintf("app.kubernetes.io/name=%s", "node-agent")
	err = waitForPod(k8sClient, "node-agent", "kubescape", label, 60)
	Expect(err).To(BeNil())

	label = fmt.Sprintf("app.kubernetes.io/name=%s", "operator")
	err = waitForPod(k8sClient, "operator", "kubescape", label, 60)
	Expect(err).To(BeNil())

	label = fmt.Sprintf("app.kubernetes.io/name=%s", "storage")
	err = waitForPod(k8sClient, "storage", "kubescape", label, 60)
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	By("tearing down test environment")
	Expect(testEnv.Stop()).ToNot(HaveOccurred())
})
