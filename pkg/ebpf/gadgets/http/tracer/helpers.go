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
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
)

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

func parseHTTPRequest(data []byte) (HTTPRequestData, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	// Use http.ReadRequest to parse the HTTP request
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return HTTPRequestData{}, err
	}
	defer req.Body.Close()

	return HTTPRequestData{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header,
	}, nil
}

func parseHTTPResponse(data []byte) (HTTPResponseData, error) {
	bufReader := bufio.NewReader(bytes.NewReader(data))

	// Read the first line to get the status
	statusLine, err := bufReader.ReadString('\n')
	if err != nil {
		return HTTPResponseData{}, fmt.Errorf("error reading status line: %v", err)
	}

	// Parse status line
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 3 {
		return HTTPResponseData{}, fmt.Errorf("invalid status line: %s", statusLine)
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return HTTPResponseData{}, fmt.Errorf("invalid status code: %v", err)
	}

	// Parse headers
	headers := make(http.Header)
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			break // End of headers or error
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue // Skip invalid header lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		headers.Add(key, value)
	}

	return HTTPResponseData{
		StatusCode: statusCode,
		Status:     strings.Join(parts[2:], " "),
		Headers:    headers,
	}, nil
}

func FromCString(in []byte) []byte {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return in[:i]
		}
	}
	return in
}

func (t *Tracer) ParseHTTP(rawSample []byte) (*types.Event, error) {
	bpfEvent := (*http_snifferHttpevent)(unsafe.Pointer(&rawSample[0]))

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, bpfEvent.OtherIp)

	httpData, err := GetHttpData(bpfEvent)
	if err != nil {
		return nil, err
	}
	logger.L().Info(string(bpfEvent.Buf[:]) + "- IP - " + ip.String())
	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: uint64(bpfEvent.Netns)},
		Pid:           bpfEvent.Pid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		Syscall:       string(bpfEvent.Syscall[:]),
		OtherPort:     bpfEvent.OtherPort,
		OtherIp:       ip.String(),
		Headers:       httpData,
	}

	return &event, nil
}
func GetHttpData(bpfEvent *http_snifferHttpevent) (types.HTTPData, error) {
	switch bpfEvent.Type {
	case EVENT_TYPE_REQUEST:
		httpData, err := parseHTTPRequest(FromCString(bpfEvent.Buf[:]))
		if err != nil {
			return nil, err
		}
		return httpData, nil
	case EVENT_TYPE_RESPONSE:
		httpData, err := parseHTTPResponse(FromCString(bpfEvent.Buf[:]))
		if err != nil {
			return nil, err
		}
		return httpData, nil
	default:
		return nil, fmt.Errorf("unknown event type: %d", bpfEvent.Type)
	}

}
