package containerprofilemanager

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func buildNetworkPorts(protocol string, ports []uint16) []v1beta1.NetworkPort {
	networkPorts := make([]v1beta1.NetworkPort, 0, len(ports))
	for _, port := range ports {
		networkPorts = append(networkPorts, v1beta1.NetworkPort{
			Protocol: v1beta1.Protocol(protocol),
			Port:     ptr.To(int32(port)),
			Name:     generatePortIdentifier(protocol, int32(port)),
		})
	}
	return networkPorts
}

func resolveServiceEnforcementPorts(
	k8sClient k8sclient.K8sClientInterface,
	namespace, serviceName string,
	svc k8sinterface.IWorkload,
	observedPort uint16,
	protocol string,
) []uint16 {
	if svc == nil {
		return []uint16{observedPort}
	}

	var service corev1.Service
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(svc.GetObject(), &service); err != nil {
		logger.L().Warning("failed to convert service for port resolution",
			helpers.String("reason", err.Error()),
			helpers.String("service", serviceName),
			helpers.String("namespace", namespace))
		return []uint16{observedPort}
	}

	normalizedProto := normalizeProtocol(protocol)
	for _, sp := range service.Spec.Ports {
		if sp.Port != int32(observedPort) {
			continue
		}
		if !protocolsMatch(sp.Protocol, normalizedProto) {
			continue
		}

		switch sp.TargetPort.Type {
		case intstr.Int:
			if sp.TargetPort.IntVal > 0 {
				return []uint16{uint16(sp.TargetPort.IntVal)}
			}
			return []uint16{uint16(sp.Port)}
		case intstr.String:
			if port, ok := parseNumericPortString(sp.TargetPort.StrVal); ok {
				return []uint16{port}
			}
			if ports := resolveEndpointPortsByServicePortName(k8sClient, namespace, serviceName, sp.Name, protocol); len(ports) > 0 {
				return ports
			}
			return []uint16{observedPort}
		default:
			return []uint16{uint16(sp.Port)}
		}
	}

	return []uint16{observedPort}
}

func resolveEndpointPortsByServicePortName(
	k8sClient k8sclient.K8sClientInterface,
	namespace, serviceName, servicePortName, protocol string,
) []uint16 {
	if k8sClient == nil {
		return nil
	}

	normalizedProto := normalizeProtocol(protocol)
	if ports := collectEndpointSlicePorts(k8sClient, namespace, serviceName, servicePortName, normalizedProto); len(ports) > 0 {
		return dedupeSortPorts(ports)
	}
	if ports := collectEndpointsPorts(k8sClient, namespace, serviceName, servicePortName, normalizedProto); len(ports) > 0 {
		return dedupeSortPorts(ports)
	}
	return nil
}

func collectEndpointSlicePorts(
	k8sClient k8sclient.K8sClientInterface,
	namespace, serviceName, servicePortName string,
	normalizedProto corev1.Protocol,
) []uint16 {
	client := k8sClient.GetKubernetesClient()
	if client == nil {
		return nil
	}

	slices, err := client.DiscoveryV1().EndpointSlices(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + serviceName,
	})
	if err != nil {
		if apierrors.IsForbidden(err) {
			logger.L().Debug("endpointslice list forbidden, falling back to endpoints",
				helpers.String("service", serviceName),
				helpers.String("namespace", namespace))
		} else {
			logger.L().Warning("failed to list endpointslices",
				helpers.String("reason", err.Error()),
				helpers.String("service", serviceName),
				helpers.String("namespace", namespace))
		}
		return nil
	}

	var ports []uint16
	for i := range slices.Items {
		for _, endpointPort := range slices.Items[i].Ports {
			if !endpointSlicePortMatches(endpointPort, servicePortName, normalizedProto) {
				continue
			}
			if endpointPort.Port != nil {
				ports = append(ports, uint16(*endpointPort.Port))
			}
		}
	}
	return ports
}

func collectEndpointsPorts(
	k8sClient k8sclient.K8sClientInterface,
	namespace, serviceName, servicePortName string,
	normalizedProto corev1.Protocol,
) []uint16 {
	endpointsObj, err := k8sClient.GetWorkload(namespace, "Endpoints", serviceName)
	if err != nil {
		logger.L().Debug("failed to get endpoints for port resolution",
			helpers.String("reason", err.Error()),
			helpers.String("service", serviceName),
			helpers.String("namespace", namespace))
		return nil
	}

	var endpoints corev1.Endpoints
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(endpointsObj.GetObject(), &endpoints); err != nil {
		logger.L().Warning("failed to convert endpoints for port resolution",
			helpers.String("reason", err.Error()),
			helpers.String("service", serviceName),
			helpers.String("namespace", namespace))
		return nil
	}

	var ports []uint16
	for _, subset := range endpoints.Subsets {
		for _, endpointPort := range subset.Ports {
			if !endpointPortMatches(endpointPort, servicePortName, normalizedProto) {
				continue
			}
			ports = append(ports, uint16(endpointPort.Port))
		}
	}
	return ports
}

func endpointSlicePortMatches(port discoveryv1.EndpointPort, servicePortName string, normalizedProto corev1.Protocol) bool {
	if port.Name == nil || *port.Name != servicePortName {
		return false
	}
	if port.Protocol != nil && !protocolsMatch(*port.Protocol, normalizedProto) {
		return false
	}
	return port.Port != nil
}

func endpointPortMatches(port corev1.EndpointPort, servicePortName string, normalizedProto corev1.Protocol) bool {
	if port.Name != servicePortName {
		return false
	}
	if port.Protocol != "" && !protocolsMatch(port.Protocol, normalizedProto) {
		return false
	}
	return port.Port > 0
}

func normalizeProtocol(protocol string) corev1.Protocol {
	switch strings.ToUpper(protocol) {
	case string(corev1.ProtocolUDP):
		return corev1.ProtocolUDP
	case string(corev1.ProtocolSCTP):
		return corev1.ProtocolSCTP
	default:
		return corev1.ProtocolTCP
	}
}

func protocolsMatch(left, right corev1.Protocol) bool {
	if left == "" {
		left = corev1.ProtocolTCP
	}
	if right == "" {
		right = corev1.ProtocolTCP
	}
	return left == right
}

func parseNumericPortString(value string) (uint16, bool) {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

func dedupeSortPorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}

	seen := make(map[uint16]struct{}, len(ports))
	unique := make([]uint16, 0, len(ports))
	for _, port := range ports {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		unique = append(unique, port)
	}

	sort.Slice(unique, func(i, j int) bool { return unique[i] < unique[j] })
	return unique
}

func networkPortValues(ports []v1beta1.NetworkPort) []int32 {
	values := make([]int32, 0, len(ports))
	for _, port := range ports {
		if port.Port == nil {
			continue
		}
		values = append(values, *port.Port)
	}
	return values
}
