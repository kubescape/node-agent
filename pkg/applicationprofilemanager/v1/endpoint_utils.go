package applicationprofilemanager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	tracerhttphelper "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func GetNewEndpoint(request *tracerhttptype.HTTPRequest, event *tracerhttptype.Event, url string) (*v1beta1.HTTPEndpoint, error) {
	internal := tracerhttptype.IsInternal(event.OtherIp)

	direction, err := event.GetPacketDirection()
	if err != nil {
		logger.L().Debug("failed to get packet direction", helpers.Error(err))
		return nil, err
	}

	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)
	rawJSON, err := json.Marshal(headers)
	if err != nil {
		logger.L().Error("Error marshaling JSON:", helpers.Error(err))
		return nil, err
	}

	return &v1beta1.HTTPEndpoint{
		Endpoint:  url,
		Methods:   []string{request.Method},
		Internal:  internal,
		Direction: direction,
		Headers:   rawJSON}, nil
}

func (am *ApplicationProfileManager) GetEndpointIdentifier(request *tracerhttptype.HTTPRequest) (string, error) {
	identifier := request.URL
	headers := tracerhttphelper.ExtractConsistentHeaders(request.Headers)
	if host, ok := headers["Host"]; ok {
		host := host[0]
		_, port, err := net.SplitHostPort(host)
		if err != nil {
			port = "80"
		}
		identifier = ":" + port + identifier
	}

	return identifier, nil
}

func CalculateHTTPEndpointHash(endpoint *v1beta1.HTTPEndpoint) string {
	hash := sha256.New()

	hash.Write([]byte(endpoint.Endpoint))

	sortedMethods := make([]string, len(endpoint.Methods))
	copy(sortedMethods, endpoint.Methods)
	sort.Strings(sortedMethods)

	hash.Write([]byte(strings.Join(sortedMethods, ",")))
	hash.Write(endpoint.Headers)

	return hex.EncodeToString(hash.Sum(nil))
}
