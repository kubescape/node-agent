package applicationprofilemanager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	tracerhttphelper "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func GetNewEndpoint(event *tracerhttptype.Event, identifier string) (*v1beta1.HTTPEndpoint, error) {
	headers := tracerhttphelper.ExtractConsistentHeaders(event.Request.Header)
	headers["Host"] = []string{event.Request.Host}
	rawJSON, err := json.Marshal(headers)
	if err != nil {
		logger.L().Error("Error marshaling JSON:", helpers.Error(err))
		return nil, err
	}

	return &v1beta1.HTTPEndpoint{
		Endpoint:  identifier,
		Methods:   []string{event.Request.Method},
		Internal:  event.Internal,
		Direction: event.Direction,
		Headers:   rawJSON}, nil
}

func (am *ApplicationProfileManager) GetEndpointIdentifier(request *tracerhttptype.Event) (string, error) {
	identifier := request.Request.URL.String()
	if host := request.Request.Host; host != "" {

		if !isValidHost(host) {
			return "", fmt.Errorf("invalid host: %s", host)
		}

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

	hash.Write([]byte(endpoint.Direction))

	return hex.EncodeToString(hash.Sum(nil))
}

func isValidHost(host string) bool {
	// Check if the host is empty
	if host == "" {
		return false
	}

	// Check if host contains spaces or invalid characters
	if strings.ContainsAny(host, " \t\r\n") {
		return false
	}

	// Parse the host using http's standard URL parser
	if _, err := url.ParseRequestURI("http://" + host); err != nil {
		return false
	}

	return true
}
