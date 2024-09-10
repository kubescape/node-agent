package applicationprofilemanager

import (
	"encoding/json"
	"fmt"
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	tracerhttphelper "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func (am *ApplicationProfileManager) GetEndpoint(k8sContainerID string, request *tracerhttptype.HTTPRequestData, event *tracerhttptype.Event, url string) (*v1beta1.HTTPEndpoint, error) {
	endpoint, err := am.GetSavedEndpoint(k8sContainerID, url)
	if err != nil {
		return GetNewEndpoint(request, event, url)
	}

	if !slices.Contains(endpoint.Methods, request.Method) {
		endpoint.Methods = append(endpoint.Methods, request.Method)
		return endpoint, nil
	}

	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)
	endpointHeaders, err := endpoint.GetHeaders()
	if err != nil {
		if newHost, ok := request.Headers["Host"]; ok && len(newHost) > 0 {
			if existing, ok := headers["Host"]; ok && len(existing) > 0 {
				if existing[0] != newHost[0] {
					return GetNewEndpoint(request, event, url)
				}
			}
		}

		if tracerhttphelper.HeadersAreDifferent(endpointHeaders, headers) {
			endpoint.Headers = mergeHeaders(endpointHeaders, headers)
			return endpoint, nil
		}
	}

	return nil, fmt.Errorf("endpoint already exists")
}

func (am *ApplicationProfileManager) GetSavedEndpoint(k8sContainerID string, url string) (*v1beta1.HTTPEndpoint, error) {
	savedHttpEndpoints := am.savedHttpEndpoints.Get(k8sContainerID)
	saveHttp := am.toSaveHttpEndpoints.Get(k8sContainerID)

	if savedHttpEndpoints != nil {
		if endpoint := savedHttpEndpoints.Get(url); endpoint != nil {
			return endpoint, nil
		}
	}
	if saveHttp != nil {
		if endpoint := saveHttp.Get(url); endpoint != nil {
			return endpoint, nil
		}
	}
	return nil, fmt.Errorf("endpoint not found")
}

func GetNewEndpoint(request *tracerhttptype.HTTPRequestData, event *tracerhttptype.Event, url string) (*v1beta1.HTTPEndpoint, error) {
	internal := tracerhttptype.IsInternal(event.OtherIp)

	direction, err := tracerhttptype.GetPacketDirection(event)
	if err != nil {
		logger.L().Debug("failed to get packet direction", helpers.Error(err))
		return nil, err
	}

	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)

	rawJSON, err := json.Marshal(headers)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	return &v1beta1.HTTPEndpoint{
		Endpoint:  url,
		Methods:   []string{request.Method},
		Internal:  internal,
		Direction: direction,
		Headers:   rawJSON}, nil
}

func (am *ApplicationProfileManager) GetURL(request *tracerhttptype.HTTPRequestData) (string, error) {
	url := request.URL
	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)
	if host, ok := headers["Host"]; ok {
		url = host[0] + request.URL
	}

	return url, nil
}

func mergeHeaders(existing, new map[string][]string) json.RawMessage {

	for k, v := range new {
		if _, exists := existing[k]; exists {
			set := mapset.NewSet[string](append(existing[k], v...)...)
			existing[k] = set.ToSlice()
		} else {
			existing[k] = v
		}
	}

	rawJSON, err := json.Marshal(existing)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil
	}

	return rawJSON
}
