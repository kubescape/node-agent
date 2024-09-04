package applicationprofilemanager

import (
	"fmt"
	"slices"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	tracerhttphelper "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func GetNewEndpoint(request *tracerhttptype.HTTPRequestData, event *tracerhttptype.Event, url string) (*v1beta1.HTTPEndpoint, error) {
	internal := tracerhttptype.IsInternal(event.OtherIp)

	direction, err := tracerhttptype.GetPacketDirection(event)
	if err != nil {
		logger.L().Debug("failed to get packet direction", helpers.Error(err))
		return nil, err
	}

	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)

	return &v1beta1.HTTPEndpoint{
		Endpoint:  url,
		Methods:   []string{request.Method},
		Internal:  internal,
		Direction: direction,
		Headers:   headers}, nil
}

func (am *ApplicationProfileManager) GetURL(request *tracerhttptype.HTTPRequestData) (string, error) {
	url := request.URL
	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)
	if host, ok := headers["Host"]; ok {
		url = host[0] + request.URL
	}

	return url, nil
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
	if host, ok := request.Headers["Host"]; ok && endpoint.Headers["Host"][0] != host[0] {
		return GetNewEndpoint(request, event, url)
	}

	if tracerhttphelper.HeadersAreDifferent(endpoint.Headers, headers) {
		return GetNewEndpoint(request, event, url)
	}

	return nil, fmt.Errorf("endpoint already exists")
}
