package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
)

func (t *Tracer) ParseHTTP(rawSample []byte) (*tracerhttptype.Event, error) {
	bpfEvent := (*http_snifferHttpevent)(unsafe.Pointer(&rawSample[0]))

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, bpfEvent.OtherIp)

	httpData, err := GetHttpData(bpfEvent)
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
		Syscall:       gadgets.FromCString(bpfEvent.Syscall[:]),
		OtherPort:     bpfEvent.OtherPort,
		OtherIp:       ip.String(),
		DataType:      tracerhttptype.HTTPDataType(bpfEvent.Type),
		HttpData:      httpData,
	}

	return &event, nil
}

func GetHttpData(bpfEvent *http_snifferHttpevent) (tracerhttptype.HTTPData, error) {
	switch tracerhttptype.HTTPDataType(bpfEvent.Type) {
	case tracerhttptype.Request:
		httpData, err := parseHTTPRequest(FromCString(bpfEvent.Buf[:]))
		if err != nil {
			return nil, err
		}
		return httpData, nil
	case tracerhttptype.Response:
		httpData, err := parseHTTPResponse(FromCString(bpfEvent.Buf[:]))
		if err != nil {
			return nil, err
		}
		return httpData, nil
	default:
		return nil, fmt.Errorf("unknown event type: %d", bpfEvent.Type)
	}
}

func parseHTTPRequest(data []byte) (tracerhttptype.HTTPRequest, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return tracerhttptype.HTTPRequest{}, err
	}
	defer req.Body.Close()
	headers := req.Header.Clone()
	headers.Set("Host", req.Host)

	return tracerhttptype.HTTPRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: headers,
	}, nil
}

func parseHTTPResponse(data []byte) (tracerhttptype.HTTPResponse, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	statusLine, err := bufReader.ReadString('\n')
	if err != nil {
		return tracerhttptype.HTTPResponse{}, fmt.Errorf("error reading status line: %v", err)
	}

	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 3 {
		return tracerhttptype.HTTPResponse{}, fmt.Errorf("invalid status line: %s", statusLine)
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return tracerhttptype.HTTPResponse{}, fmt.Errorf("invalid status code: %v", err)
	}

	headers := make(http.Header)
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		headers.Add(key, value)
	}

	return tracerhttptype.HTTPResponse{
		StatusCode: statusCode,
		Status:     strings.Join(parts[2:], " "),
		Headers:    headers,
	}, nil
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
