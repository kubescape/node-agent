package types

import (
	"fmt"
	"net"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

func GetPacketDirection(syscall string) (consts.NetworkDirection, error) {
	if readSyscalls[syscall] {
		return consts.Inbound, nil
	} else if writeSyscalls[syscall] {
		return consts.Outbound, nil
	} else {
		return "", fmt.Errorf("unknown syscall %s", syscall)
	}
}

func IsInternal(ip string) bool {
	ipAddress := net.ParseIP(ip)
	return ipAddress.IsPrivate()
}

func GetColumns() *columns.Columns[Event] {
	httpColumns := columns.MustCreateColumns[Event]()
	return httpColumns
}
