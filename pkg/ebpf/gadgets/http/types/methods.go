package types

import (
	"fmt"
	"net"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

func (event *Event) GetPacketDirection() (consts.NetworkDirection, error) {
	if readSyscalls[event.Syscall] {
		return consts.Inbound, nil
	} else if writeSyscalls[event.Syscall] {
		return consts.Outbound, nil
	} else {
		return "", fmt.Errorf("unknown syscall %s", event.Syscall)
	}
}

func (event *Event) GetUniqueIdentifier() string {
	return string(event.Pid) + string(event.Sockfd)
}

func IsInternal(ip string) bool {
	ipAddress := net.ParseIP(ip)
	return ipAddress.IsPrivate()
}

func GetColumns() *columns.Columns[Event] {
	httpColumns := columns.MustCreateColumns[Event]()
	return httpColumns
}

func Base(ev eventtypes.Event) *GroupedHTTP {
	return &GroupedHTTP{
		Event: ev,
	}
}
