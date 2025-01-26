package applicationprofilemanager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	tracerhttphelper "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func GetNewEndpoint(event *tracerhttptype.Event, identifier string) (*v1beta1.HTTPEndpoint, error) {
	headers := tracerhttphelper.ExtractConsistentHeaders(event.Request.Header)
	headers["Host"] = []string{event.Request.Host}
	rawJSON, err := json.Marshal(headers)
	if err != nil {
		logger.L().Debug("GetNewEndpoint - error marshaling headers", helpers.Error(err), helpers.Interface("headers", headers))
		return nil, err
	}

	return &v1beta1.HTTPEndpoint{
		Endpoint:  identifier,
		Methods:   []string{event.Request.Method},
		Internal:  event.Internal,
		Direction: event.Direction,
		Headers:   rawJSON}, nil
}

func GetEndpointIdentifier(request *tracerhttptype.Event) (string, error) {
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
	if host == "" {
		return false
	}

	if strings.ContainsAny(host, " \t\r\n") {
		return false
	}

	if _, err := url.ParseRequestURI("http://" + host); err != nil {
		return false
	}

	return true
}

func IsPolicyIncluded(existingPolicy, newPolicy *v1beta1.RulePolicy) bool {
	if existingPolicy == nil {
		return false
	}

	if newPolicy.AllowedContainer && !existingPolicy.AllowedContainer {
		return false
	}

	for _, newProcess := range newPolicy.AllowedProcesses {
		if !slices.Contains(existingPolicy.AllowedProcesses, newProcess) {
			return false
		}
	}

	return true
}

func GetInitOperations(ruleCreator ruleengine.RuleCreator, containerType string, containerIndex int) []utils.PatchOperation {
	var operations []utils.PatchOperation

	ids := ruleCreator.GetAllRuleIDs()
	rulePoliciesMap := make(map[string]v1beta1.RulePolicy)
	for _, id := range ids {
		rulePoliciesMap[id] = v1beta1.RulePolicy{
			AllowedContainer: false,
			AllowedProcesses: []string{},
		}
	}

	createMap := utils.PatchOperation{
		Op:    "replace",
		Path:  fmt.Sprintf("/spec/%s/%d/rulePolicies", containerType, containerIndex),
		Value: rulePoliciesMap,
	}

	operations = append(operations, createMap)

	return operations
}
