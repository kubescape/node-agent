package tracer

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
