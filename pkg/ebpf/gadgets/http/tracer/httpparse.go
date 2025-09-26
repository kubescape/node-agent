package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

	request, err := ParseHttpRequest(FromCString(bpfEvent.Buf[:]))
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

func ParseHttpRequest(data []byte) (*http.Request, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return fallbackReadRequest(data)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(body))

	return req, nil
}

func ParseHttpResponse(data []byte, req *http.Request) (*http.Response, error) {
	resp, err := readResponse(data, req)
	if err != nil {
		return fallbackReadResponse(data, req)
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
	return strconv.FormatUint(event.SocketInode, 10) + strconv.FormatUint(uint64(event.SockFd), 10)
}

func ToTime(t eventtypes.Time) time.Time {
	return time.Unix(0, int64(t))
}

func PatchHTTPPacket(data []byte) []byte {
	if bytes.HasSuffix(data, []byte("\r\n\r\n")) {
		return data
	}

	if bytes.HasSuffix(data, []byte("\n\n")) {
		return bytes.ReplaceAll(data, []byte("\n\n"), []byte("\r\n\r\n"))
	}

	if bytes.HasSuffix(data, []byte("\r\n")) {
		return append(data, []byte("\r\n")...)
	}

	if bytes.HasSuffix(data, []byte("\n")) {
		return append(data, []byte("\r\n")...)
	}

	return append(data, []byte("\r\n\r\n")...)
}

func fallbackReadRequest(data []byte) (*http.Request, error) {
	cleanedData, err := cleanCorrupted(data)
	if err != nil {
		return nil, fmt.Errorf("failed to clean request data: %w", err)
	}

	bufReader := bufio.NewReader(bytes.NewReader(PatchHTTPPacket(cleanedData)))
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request even after removing last line: %w", err)
	}

	return req, nil
}

func fallbackReadResponse(data []byte, req *http.Request) (*http.Response, error) {
	cleanedData, err := cleanCorrupted(data)
	if err != nil {
		return nil, fmt.Errorf("failed to clean response data: %w", err)
	}

	resp, err := readResponse(cleanedData, req)
	if err != nil {
		return nil, fmt.Errorf("failed to read response even after removing last line: %w", err)
	}

	return resp, nil
}

func readResponse(data []byte, req *http.Request) (*http.Response, error) {
	bufReader := bufio.NewReader(bytes.NewReader(PatchHTTPPacket(data)))
	resp, err := http.ReadResponse(bufReader, req)
	return resp, err
}

func cleanCorrupted(data []byte) ([]byte, error) {
	lastNewline := bytes.LastIndex(data, []byte("\n"))
	if lastNewline == -1 {
		return nil, fmt.Errorf("failed to find newline in request data")
	}

	cleanedData := data[:lastNewline+1]

	return cleanedData, nil
}
