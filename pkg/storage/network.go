package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/evanphx/json-patch"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
)

func (sc *StorageHttpClientMock) GetNetworkNeighborhood(_, _ string) (*v1beta1.NetworkNeighborhood, error) {
	if len(sc.NetworkNeighborhoods) == 0 {
		return &v1beta1.NetworkNeighborhood{
			Spec: v1beta1.NetworkNeighborhoodSpec{
				Containers: []v1beta1.NetworkNeighborhoodContainer{
					// FIXME add stuff
				},
			},
		}, nil
	}
	return sc.NetworkNeighborhoods[len(sc.NetworkNeighborhoods)-1], nil
}

func (sc *StorageHttpClientMock) CreateNetworkNeighborhood(neighborhood *v1beta1.NetworkNeighborhood, _ string) error {
	if !sc.failedOnce {
		sc.failedOnce = true
		return errors.New("first time fail")
	}
	for i := range neighborhood.Spec.Containers {
		if neighborhood.Spec.Containers[i].Ingress == nil {
			neighborhood.Spec.Containers[i].Ingress = []v1beta1.NetworkNeighbor{}
		}
		if neighborhood.Spec.Containers[i].Egress == nil {
			neighborhood.Spec.Containers[i].Egress = []v1beta1.NetworkNeighbor{}
		}
	}
	sc.NetworkNeighborhoods = append(sc.NetworkNeighborhoods, neighborhood)
	return nil
}

func (sc *StorageHttpClientMock) PatchNetworkNeighborhood(name, _ string, patchJSON []byte, _ chan error) error {
	if len(sc.NetworkNeighborhoods) == 0 {
		return errors2.NewNotFound(v1beta1.Resource("networkneighborhood"), name)
	}
	// get last neighborhood
	lastNeighborhood, err := json.Marshal(sc.NetworkNeighborhoods[len(sc.NetworkNeighborhoods)-1])
	if err != nil {
		return fmt.Errorf("marshal last neighborhood: %w", err)
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		return fmt.Errorf("decode patch: %w", err)
	}
	patchedNeighborhood, err := patch.Apply(lastNeighborhood)
	if err != nil {
		return fmt.Errorf("apply patch: %w", err)
	}
	neighborhood := &v1beta1.NetworkNeighborhood{}
	if err := json.Unmarshal(patchedNeighborhood, neighborhood); err != nil {
		return fmt.Errorf("unmarshal patched neighborhood: %w", err)
	}
	sc.NetworkNeighborhoods = append(sc.NetworkNeighborhoods, neighborhood)
	return nil
}
