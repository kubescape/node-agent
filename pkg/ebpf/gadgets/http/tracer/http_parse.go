package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
)

func CreateEventFromRequest(bpfEvent *http_snifferHttpevent) (*tracerhttptype.Event, error) {

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, bpfEvent.OtherIp)

	request, err := ParseHTTPRequest(FromCString(bpfEvent.Buf[:]))
	if err != nil {
		return nil, err
	}

	direction, err := tracerhttptype.GetPacketDirection(gadgets.FromCString(bpfEvent.Syscall[:]))
	if err != nil {
		return nil, err
	}

	event := tracerhttptype.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		Pid:           bpfEvent.Pid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		OtherPort:     bpfEvent.OtherPort,
		OtherIp:       ip.String(),
		Request:       request,
		Internal:      tracerhttptype.IsInternal(ip.String()),
		Direction:     direction,
	}

	return &event, nil
}

func ParseHTTPRequest(data []byte) (*http.Request, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()

	return req, nil
}

func ParseHTTPResponse(data []byte, req *http.Request) (*http.Response, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	resp, err := http.ReadResponse(bufReader, req)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return resp, nil
}

func ExtractConsistentHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string)
	for _, header := range tracerhttptype.ConsistentHeaders {
		if value, ok := headers[header]; ok {
			switch typedValue := interface{}(value).(type) {
			case []string:
				result[header] = typedValue
			case string:
				result[header] = []string{typedValue}
			default:
				result[header] = []string{fmt.Sprint(typedValue)}
			}
		}
	}
	return result
}

func FromCString(in []byte) []byte {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return in[:i]
		}
	}
	return in
}

func GetUniqueIdentifier(event *http_snifferHttpevent) string {
	return strconv.FormatUint(uint64(event.Pid), 10) + strconv.FormatUint(uint64(event.SockFd), 10)
}

func ToTime(t eventtypes.Time) time.Time {
	return time.Unix(0, int64(t))
}
