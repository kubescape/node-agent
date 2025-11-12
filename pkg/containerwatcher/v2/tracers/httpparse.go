package tracers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

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

var ConsistentHeaders = []string{
	"Accept-Encoding",
	"Accept-Language",
	"Connection",
	"Host",
	"Upgrade-Insecure-Requests",
}

func CreateEventFromRequest(bpfEvent utils.HttpRawEvent) (utils.HttpEvent, error) {
	request, err := ParseHttpRequest(FromCString(bpfEvent.GetBuf()))
	if err != nil {
		return nil, err
	}

	direction, err := GetPacketDirection(bpfEvent.GetSyscall())
	if err != nil {
		return nil, err
	}

	return bpfEvent.MakeHttpEvent(request, direction), nil
}

func ExtractConsistentHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string)
	for _, header := range ConsistentHeaders {
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

func GetPacketDirection(syscall string) (consts.NetworkDirection, error) {
	if readSyscalls[syscall] {
		return consts.Inbound, nil
	} else if writeSyscalls[syscall] {
		return consts.Outbound, nil
	} else {
		return "", fmt.Errorf("unknown syscall %s", syscall)
	}
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

func FromCString(in []byte) []byte {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return in[:i]
		}
	}
	return in
}

func GetUniqueIdentifier(event utils.HttpRawEvent) string {
	return strconv.FormatUint(event.GetSocketInode(), 10) + strconv.FormatUint(uint64(event.GetSockFd()), 10)
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
