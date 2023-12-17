package sensor

import (
	"context"
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

type OpenPortsStatus struct {
	TcpPorts  []procspy.Connection `json:"tcpPorts"`
	UdpPorts  []procspy.Connection `json:"udpPorts"`
	ICMPPorts []procspy.Connection `json:"icmpPorts"`
}

func getOpenedPorts(pathsList []string) ([]procspy.Connection, error) {
	res := make([]procspy.Connection, 0)
	for netPathIdx := range pathsList {
		bytesBuf, err := os.ReadFile(pathsList[netPathIdx])
		if err != nil {
			return res, fmt.Errorf("failed to ReadFile(%s): %v", pathsList[netPathIdx], err)
		}
		netCons := procspy.NewProcNet(bytesBuf, tcpListeningState)
		for c := netCons.Next(); c != nil; c = netCons.Next() {
			res = append(res, *c)
		}
	}
	return res, nil
}

func SenseOpenPorts(ctx context.Context) (*OpenPortsStatus, error) {
	// TODO: take process name. walks on ProcNetTCPPaths for each process in the system
	res := OpenPortsStatus{TcpPorts: make([]procspy.Connection, 0)}
	// tcp
	ports, err := getOpenedPorts(ProcNetTCPPaths)
	if err != nil {
		logger.L().Ctx(ctx).Warning("In SenseOpenPorts", helpers.String("paths", fmt.Sprintf("%v", ProcNetTCPPaths)), helpers.Error(err))
	} else {
		res.TcpPorts = ports
	}
	// udp
	ports, err = getOpenedPorts(ProcNetUDPPaths)
	if err != nil {
		logger.L().Ctx(ctx).Warning("In SenseOpenPorts", helpers.String("paths", fmt.Sprintf("%v", ProcNetUDPPaths)), helpers.Error(err))
	} else {
		res.UdpPorts = ports
	}
	// icmp
	ports, err = getOpenedPorts(ProcNetICMPPaths)
	if err != nil {
		logger.L().Ctx(ctx).Warning("In SenseOpenPorts", helpers.String("paths", fmt.Sprintf("%v", ProcNetICMPPaths)), helpers.Error(err))
	} else {
		res.ICMPPorts = ports
	}
	return &res, nil
}
