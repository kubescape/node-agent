package tracers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

var bufioReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReader(nil)
	},
}

func getBufioReader(r io.Reader) *bufio.Reader {
	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}

var ConsistentHeaders = []string{
	"Accept-Encoding",
	"Accept-Language",
	"Connection",
	"Host",
	"Upgrade-Insecure-Requests",
}

func CreateEventFromRequest(bpfEvent utils.HttpRawEvent) (utils.HttpEvent, error) {
	request, err := ParseHttpRequest(GetValidBuf(bpfEvent))
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
	switch syscall {
	case "read", "readv", "recvfrom", "recvmsg":
		return consts.Inbound, nil
	case "write", "writev", "sendto", "sendmsg":
		return consts.Outbound, nil
	default:
		return "", fmt.Errorf("unknown syscall %s", syscall)
	}
}

func ParseHttpRequest(data []byte) (*http.Request, error) {
	// Find header/body boundary
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		if headerEnd == -1 {
			return fallbackReadRequest(data)
		}
		headerEnd += 2
	} else {
		headerEnd += 4
	}

	// Parse headers only
	bufReader := getBufioReader(bytes.NewReader(data[:headerEnd]))
	defer putBufioReader(bufReader)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return fallbackReadRequest(data)
	}

	// Set body directly without re-reading.
	// Use Content-Length (when present) to discard trailing garbage from the
	// fixed-size BPF ring-buffer.  The kernel-side gadget submits the entire
	// 4 KiB struct regardless of how many bytes were actually captured, so
	// everything past the real payload is uninitialised memory.
	bodyData := data[headerEnd:]
	if len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
		decodedBody, err := io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(bodyData)))
		if err == nil {
			bodyData = decodedBody
			req.TransferEncoding = nil
			req.Header.Del("Transfer-Encoding")
			req.Header.Del("Content-Length")
		}
	}
	if req.ContentLength >= 0 && req.ContentLength < int64(len(bodyData)) {
		bodyData = bodyData[:req.ContentLength]
	}
	req.ContentLength = int64(len(bodyData))
	req.Body = io.NopCloser(bytes.NewReader(bodyData))

	return req, nil
}

func ParseHttpResponse(data []byte, req *http.Request) (*http.Response, error) {
	// Find header/body boundary
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		if headerEnd == -1 {
			return fallbackReadResponse(data, req)
		}
		headerEnd += 2
	} else {
		headerEnd += 4
	}

	// Parse headers only
	bufReader := getBufioReader(bytes.NewReader(data[:headerEnd]))
	defer putBufioReader(bufReader)
	resp, err := http.ReadResponse(bufReader, req)
	if err != nil {
		return fallbackReadResponse(data, req)
	}

	// Set body directly without re-reading.
	// See ParseHttpRequest for why we need the Content-Length guard.
	bodyData := data[headerEnd:]
	if len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
		decodedBody, err := io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(bodyData)))
		if err == nil {
			bodyData = decodedBody
		}
	}
	if resp.ContentLength >= 0 && resp.ContentLength < int64(len(bodyData)) {
		bodyData = bodyData[:resp.ContentLength]
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyData))
	resp.ContentLength = int64(len(bodyData))
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("Content-Length")

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

// GetValidBuf returns only the valid portion of the BPF event buffer.
// It uses buf_len set by the gadget to determine the actual data length.
func GetValidBuf(event utils.HttpRawEvent) []byte {
	buf := event.GetBuf()
	if n := event.GetBufLen(); n > 0 && int(n) <= len(buf) {
		return buf[:n]
	}
	return buf
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

func detachBody(body io.ReadCloser) io.ReadCloser {
	if body == nil {
		return nil
	}
	bodyBytes, _ := io.ReadAll(body)
	_ = body.Close()
	return io.NopCloser(bytes.NewReader(bodyBytes))
}

func fallbackReadRequest(data []byte) (*http.Request, error) {
	cleanedData, err := cleanCorrupted(data)
	if err != nil {
		return nil, fmt.Errorf("failed to clean request data: %w", err)
	}

	bufReader := getBufioReader(bytes.NewReader(PatchHTTPPacket(cleanedData)))
	defer putBufioReader(bufReader)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request even after removing last line: %w", err)
	}

	if req.Body != nil {
		req.Body = detachBody(req.Body)
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
	bufReader := getBufioReader(bytes.NewReader(PatchHTTPPacket(data)))
	defer putBufioReader(bufReader)
	resp, err := http.ReadResponse(bufReader, req)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		resp.Body = detachBody(resp.Body)
	}
	return resp, nil
}

func cleanCorrupted(data []byte) ([]byte, error) {
	lastNewline := bytes.LastIndex(data, []byte("\n"))
	if lastNewline == -1 {
		return nil, fmt.Errorf("failed to find newline in request data")
	}

	cleanedData := data[:lastNewline+1]

	return cleanedData, nil
}
