package e2e

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	. "github.com/onsi/ginkgo/v2"
)

var (
	//go:embed testdata/nginx-sbomspdx.json
	nginxSbomSpdxBytes []byte
)

var _ = Describe("GenerateFilteredSbom", func() {
	JustBeforeEach(func() {
		sbom := &storagev1beta1.SBOMSPDXv2p3{}
		err := json.Unmarshal(nginxSbomSpdxBytes, sbom)
		if err != nil {
			fmt.Println("error", err)
			return
		}
		//for _, file := range sbom.Spec.SPDX.Files {
		//	fmt.Println(file.FileName)
		//}

		// create resource on the cluster
		path := fmt.Sprintf("/apis/%s/namespaces/%s/%s", sbom.APIVersion, sbom.Namespace, strings.ToLower(sbom.Kind))
		data, err := k8sClient.CoreV1().
			RESTClient().
			Post().
			AbsPath(path).
			Body(sbom).
			DoRaw(context.TODO())
		if err != nil {
			fmt.Println("error creating resource:", err)
		}
		fmt.Println(string(data))
	})
	It("should create a filtered sbom", func() {
		fmt.Println("It is doing nothing")
	})
})
