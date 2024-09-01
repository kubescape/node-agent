package types

import (
	"fmt"
	"net"
	"net/http"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// TODO: Import from storage types
type NetworkDirection string

const (
	Inbound  NetworkDirection = "inbound"
	Outbound NetworkDirection = "outbound"
)

var ConsistentHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Connection",
	"DNT",
	"Host",
	"Pragma",
	"Upgrade-Insecure-Requests",
	"User-Agent",
}

var writeSyscalls = map[string]bool{
	"write":   true,
	"writev":  true,
	"sendto":  true,
	"sendmsg": true,
}

var readSyscalls = map[string]bool{
	"read":     true,
	"readv":    true,
	"recvfrom": true,
	"recvmsg":  true,
}

type HTTPData interface {
}

type HTTPRequestData struct {
	Method  string
	URL     string
	Headers http.Header
}
type HTTPResponseData struct {
	StatusCode int
	Status     string
	Headers    http.Header
}
type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithNetNsID

	Pid       uint32   `json:"pid,omitempty" column:"pid,template:pid"`
	Uid       uint32   `json:"uid,omitempty" column:"uid,template:uid"`
	Gid       uint32   `json:"gid,omitempty" column:"gid,template:gid"`
	OtherPort uint16   `json:"other_port,omitempty" column:"other_port,template:other_port"`
	OtherIp   string   `json:"other_ip,omitempty" column:"other_ip,template:other_ip"`
	Syscall   string   `json:"syscall,omitempty" column:"syscall,template:syscall"`
	HttpData  HTTPData `json:"headers,omitempty" column:"headers,template:headers"`
}

func GetPacketDirection(event *Event) (NetworkDirection, error) {
	if readSyscalls[event.Syscall] {
		return Inbound, nil
	} else if writeSyscalls[event.Syscall] {
		return Outbound, nil
	} else {
		return "", fmt.Errorf("unknown syscall %s", event.Syscall)
	}
}

func IsInternal(ip string) bool {
	ipAddress := net.ParseIP(ip)
	return ipAddress.IsPrivate()
}
func ExtractConsistentHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)

	for _, header := range ConsistentHeaders {
		if value := headers.Get(header); value != "" {
			result[header] = value
		}
	}

	return result
}

func GetColumns() *columns.Columns[Event] {
	httpColumns := columns.MustCreateColumns[Event]()

	return httpColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
