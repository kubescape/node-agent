package e2e

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	//go:embed testdata/nginx-sbomspdx.json
	nginxSbomSpdxBytes []byte
)

var _ = Describe("Generate filtered SBOM", func() {
	sbom := &storagev1beta1.SBOMSPDXv2p3{}
	err := json.Unmarshal(nginxSbomSpdxBytes, sbom)
	if err != nil {
		fmt.Println("error unmarshaling SBOMSPDXv2p3 manifest:", err)
		return
	}
	JustBeforeEach(func() {
		time.Sleep(5 * time.Second)
		// retrieve SBOMSPDXv2p3 resource from testdata
		// create CustomResource SBOMSPDXv2p3 on the cluster
		// should be: /apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/sbomspdxv2p3s
		path := fmt.Sprintf("/apis/%s/namespaces/%s/%ss", sbom.APIVersion, sbom.Namespace, strings.ToLower(sbom.Kind))
		_, err = createCustomResource(k8sClient, path, sbom)
		Expect(err).To(BeNil())

		// create test Pod that will make node-agent generate the SBOMSPDXv2p3Filtered resource
		pod := &v1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "nginx",
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Name:  "nginx",
						Image: "nginx",
					},
				},
			},
		}
		_, err = createPod(k8sClient, pod)
		Expect(err).To(BeNil())
		err = waitForPod(k8sClient, "nginx", "default", "", 60)
		Expect(err).To(BeNil())
	})
	It("should generate a SBOMSPDXv2p3Filtered resource within 2 minutes", func() {
		// wait for ~2 minutes to let the node-agent generate the filtered resource
		path := fmt.Sprintf("/apis/%s/namespaces/%s/sbomspdxv2p3filtereds", sbom.APIVersion, sbom.Namespace)
		fmt.Println(path)
		err := waitForCustomResource(k8sClient, path, 150)
		Expect(err).To(BeNil())
	})
})
