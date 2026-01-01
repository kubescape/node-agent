package hostsensormanager

import (
	"fmt"
	"os"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/weaveworks/procspy"
)

const (
	tcpListeningState = 10
)

var (
	ProcNetTCPPaths  = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	ProcNetUDPPaths  = []string{"/proc/net/udp", "/proc/net/udp6", "/proc/net/udplite", "/proc/net/udplite6"}
	ProcNetICMPPaths = []string{"/proc/net/icmp", "/proc/net/icmp6"}
)

// OpenPortsSensor implements the Sensor interface for open ports data
type OpenPortsSensor struct {
	nodeName string
}

// NewOpenPortsSensor creates a new open ports sensor
func NewOpenPortsSensor(nodeName string) *OpenPortsSensor {
	return &OpenPortsSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *OpenPortsSensor) GetKind() string {
	return "OpenPorts"
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *OpenPortsSensor) GetPluralKind() string {
	return "openports"
}

// Sense collects the open ports data from the host
func (s *OpenPortsSensor) Sense() (interface{}, error) {
	res := &OpenPortsSpec{
		TcpPorts:  make([]Connection, 0),
		UdpPorts:  make([]Connection, 0),
		ICMPPorts: make([]Connection, 0),
		NodeName:  s.nodeName,
	}

	// tcp
	ports, err := s.getOpenedPorts(ProcNetTCPPaths)
	if err != nil {
		logger.L().Warning("failed to sense TCP ports", helpers.Error(err))
	} else {
		res.TcpPorts = ports
	}

	// udp
	ports, err = s.getOpenedPorts(ProcNetUDPPaths)
	if err != nil {
		logger.L().Warning("failed to sense UDP ports", helpers.Error(err))
	} else {
		res.UdpPorts = ports
	}

	// icmp
	ports, err = s.getOpenedPorts(ProcNetICMPPaths)
	if err != nil {
		logger.L().Warning("failed to sense ICMP ports", helpers.Error(err))
	} else {
		res.ICMPPorts = ports
	}

	return res, nil
}

func (s *OpenPortsSensor) getOpenedPorts(pathsList []string) ([]Connection, error) {
	res := make([]Connection, 0)
	for _, p := range pathsList {
		hPath := hostPath(p)
		bytesBuf, err := os.ReadFile(hPath)
		if err != nil {
			return res, fmt.Errorf("failed to ReadFile(%s): %w", hPath, err)
		}
		netCons := procspy.NewProcNet(bytesBuf, tcpListeningState)
		for c := netCons.Next(); c != nil; c = netCons.Next() {
			res = append(res, Connection{
				Transport:     c.Transport,
				LocalAddress:  c.LocalAddress.String(),
				LocalPort:     c.LocalPort,
				RemoteAddress: c.RemoteAddress.String(),
				RemotePort:    c.RemotePort,
			})
		}
	}
	return res, nil
}
