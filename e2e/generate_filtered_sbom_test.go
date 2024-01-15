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

	//go:embed testdata/nginx-sbomspdx-filtered.json
	nginxSbomSpdxBytesFiltered []byte

	expectedSbom         string = "docker.io-library-nginx-sha256-2bdc49f2f8ae8d8dc50ed00f2ee56d00385c6f8bc8a8b320d0a294d9e3b49026-b49026"
	expectedSbomFiltered string = "pod-nginx-nginx-1ba5-4aaf"
)

var _ = Describe("Generate filtered SBOM", func() {
	sbom := &storagev1beta1.SBOMSPDXv2p3{}
	err := json.Unmarshal(nginxSbomSpdxBytes, sbom)
	Expect(err).To(BeNil())

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
					Image: "docker.io/library/nginx@sha256:2bdc49f2f8ae8d8dc50ed00f2ee56d00385c6f8bc8a8b320d0a294d9e3b49026",
				},
			},
		},
	}

	JustBeforeEach(func() {
		time.Sleep(10 * time.Second)
		// retrieve SBOMSPDXv2p3 resource from testdata
		// create CustomResource SBOMSPDXv2p3 on the cluster
		// should be: /apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/sbomspdxv2p3s
		path := fmt.Sprintf("/apis/%s/namespaces/%s/%ss", sbom.APIVersion, sbom.Namespace, strings.ToLower(sbom.Kind))
		_, err = createCustomResource(k8sClient, path, sbom)
		Expect(err).To(BeNil())

		// create test Pod that will make node-agent generate the SBOMSPDXv2p3Filtered resource
		_, err = createPod(k8sClient, pod)
		Expect(err).To(BeNil())
		err = waitForPod(k8sClient, "nginx", "default", "", 60)
		Expect(err).To(BeNil())
	})

	JustAfterEach(func() {
		err := deletePod(k8sClient, pod)
		Expect(err).To(BeNil())

		path := fmt.Sprintf("/apis/%s/namespaces/%s/sbomspdxv2p3s/%s", sbom.APIVersion, sbom.Namespace, expectedSbom)
		_, err = deleteCustomResourceData(k8sClient, path)
		Expect(err).To(BeNil())

		path = fmt.Sprintf("/apis/%s/namespaces/%s/sbomspdxv2p3filtereds/%s", sbom.APIVersion, sbom.Namespace, expectedSbomFiltered)
		_, err = deleteCustomResourceData(k8sClient, path)
		Expect(err).To(BeNil())
	})

	It("should generate a SBOMSPDXv2p3Filtered resource within 2 minutes", func() {
		// wait for ~2 minutes to let the node-agent generate the filtered resource
		path := fmt.Sprintf("/apis/%s/namespaces/%s/sbomspdxv2p3filtereds", sbom.APIVersion, sbom.Namespace)
		err := waitForCustomResource(k8sClient, path, 150)
		Expect(err).To(BeNil())

		// /apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/sbomspdxv2p3filtereds/pod-nginx-nginx-1ba5-4aaf
		path = fmt.Sprintf("/apis/%s/namespaces/%s/sbomspdxv2p3filtereds/%s", sbom.APIVersion, sbom.Namespace, expectedSbomFiltered)
		dataFiltered, err := getCustomResource(k8sClient, path)
		Expect(err).To(BeNil())

		// retrieve generatede filtered sbomspdx resource
		sbomFiltered := &storagev1beta1.SBOMSPDXv2p3Filtered{}
		err = json.Unmarshal(dataFiltered, sbomFiltered)
		Expect(err).To(BeNil())

		// retrieve expected filtered sbomspdx resource
		expectedSbomFiltered := &storagev1beta1.SBOMSPDXv2p3Filtered{}
		err = json.Unmarshal(nginxSbomSpdxBytesFiltered, expectedSbomFiltered)
		Expect(err).To(BeNil())

		// compare generated with filtered resources
		Expect(sbomFiltered.Annotations).To(Equal(expectedSbomFiltered.Annotations))
	})
})
