package tracers

import (
	"bytes"
	"io"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bpfBufSize = 4096 // MAX_DATAEVENT_BUFFER in program.h

// makeBPFBuffer simulates a BPF ring-buffer slot: real HTTP data followed by
// uninitialised memory (0xFF bytes with no null terminator).
func makeBPFBuffer(httpData string) []byte {
	buf := make([]byte, bpfBufSize)
	// Fill with 0xFF to simulate uninitialised memory (no null bytes).
	for i := range buf {
		buf[i] = 0xFF
	}
	copy(buf, httpData)
	return buf
}

func TestFromCString(t *testing.T) {
	t.Run("truncates at null byte", func(t *testing.T) {
		buf := []byte("hello\x00world")
		assert.Equal(t, []byte("hello"), FromCString(buf))
	})
	t.Run("returns full slice when no null byte", func(t *testing.T) {
		buf := []byte("hello")
		assert.Equal(t, []byte("hello"), FromCString(buf))
	})
	t.Run("empty input", func(t *testing.T) {
		assert.Equal(t, []byte{}, FromCString([]byte{}))
	})
}

// TestBPFBufferGarbageRequest simulates the real bug: BPF submits a 4096-byte
// struct where only the first N bytes contain valid HTTP data and the rest is
// uninitialised memory with no null terminator.
func TestBPFBufferGarbageRequest(t *testing.T) {
	httpData := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}"
	buf := makeBPFBuffer(httpData)

	// FromCString won't help — no null byte in the uninitialised region.
	cleaned := FromCString(buf)
	assert.Equal(t, bpfBufSize, len(cleaned), "FromCString should return full buffer when no null byte exists")

	// But ParseHttpRequest should still produce the correct body.
	req, err := ParseHttpRequest(cleaned)
	require.NoError(t, err)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"key":"val"}`, string(body))
}

func TestBPFBufferGarbageResponse(t *testing.T) {
	dummyReq, err := ParseHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	httpData := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	buf := makeBPFBuffer(httpData)

	cleaned := FromCString(buf)
	assert.Equal(t, bpfBufSize, len(cleaned))

	resp, err := ParseHttpResponse(cleaned, dummyReq)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

func TestBPFBufferGarbageResponse_Chunked(t *testing.T) {
	dummyReq, err := ParseHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	httpData := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
	buf := makeBPFBuffer(httpData)

	cleaned := FromCString(buf)
	assert.Equal(t, bpfBufSize, len(cleaned))

	resp, err := ParseHttpResponse(cleaned, dummyReq)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Wikipedia", string(body), "chunked response body should be decoded and should ignore trailing garbage")
}

func TestBPFBufferGarbageRequest_ContentLengthZero(t *testing.T) {
	httpData := "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	buf := makeBPFBuffer(httpData)

	cleaned := FromCString(buf)
	assert.Equal(t, bpfBufSize, len(cleaned))

	req, err := ParseHttpRequest(cleaned)
	require.NoError(t, err)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Empty(t, body, "Content-Length: 0 should produce empty body even with trailing garbage")
}

func TestBPFBufferGarbageRequest_ChunkedPost(t *testing.T) {
	httpData := "POST /api HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
	buf := makeBPFBuffer(httpData)

	cleaned := FromCString(buf)
	assert.Equal(t, bpfBufSize, len(cleaned))

	req, err := ParseHttpRequest(cleaned)
	require.NoError(t, err)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, "Wikipedia", string(body), "chunked POST body should be decoded and should ignore trailing garbage")
}

func TestFromCString_NullTerminatedBPFBuffer(t *testing.T) {
	// When BPF buffer has a null byte after the real data, FromCString truncates correctly.
	httpData := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	buf := make([]byte, bpfBufSize)
	copy(buf, httpData)
	// buf[len(httpData)] is already 0x00 (zero-value)

	cleaned := FromCString(buf)
	assert.Equal(t, len(httpData), len(cleaned))
	assert.True(t, bytes.Equal([]byte(httpData), cleaned))
}

func TestParseHttpRequest_ContentLengthTruncatesGarbage(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		expectedBody string
	}{
		{
			name:         "body truncated to content-length",
			raw:          "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloGARBAGE",
			expectedBody: "hello",
		},
		{
			name:         "body unchanged when no garbage",
			raw:          "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
			expectedBody: "hello",
		},
		{
			name:         "GET no content-length header",
			raw:          "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nhelloGARBAGE",
			expectedBody: "", // GET has no body; http.ReadRequest sets ContentLength=0
		},
		{
			name:         "POST no content-length header",
			raw:          "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nhelloGARBAGE",
			expectedBody: "", // Without Content-Length, can't distinguish body from BPF garbage
		},
		{
			name:         "empty body with content-length zero",
			raw:          "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGARBAGE",
			expectedBody: "",
		},
		{
			name:         "empty body no content-length",
			raw:          "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectedBody: "",
		},
		{
			name:         "content-length larger than body",
			raw:          "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nhello",
			expectedBody: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseHttpRequest([]byte(tt.raw))
			require.NoError(t, err)

			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBody, string(body))
		})
	}
}

func TestParseHttpResponse_ContentLengthTruncatesGarbage(t *testing.T) {
	// We need a valid request for http.ReadResponse
	dummyReq, err := ParseHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	tests := []struct {
		name         string
		raw          string
		expectedBody string
	}{
		{
			name:         "body truncated to content-length",
			raw:          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloGARBAGE",
			expectedBody: "hello",
		},
		{
			name:         "body unchanged when no garbage",
			raw:          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
			expectedBody: "hello",
		},
		{
			name:         "no content-length header",
			raw:          "HTTP/1.1 200 OK\r\n\r\nhelloGARBAGE",
			expectedBody: "helloGARBAGE",
		},
		{
			name:         "empty body with content-length zero",
			raw:          "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nGARBAGE",
			expectedBody: "",
		},
		{
			name:         "empty body no content-length",
			raw:          "HTTP/1.1 200 OK\r\n\r\n",
			expectedBody: "",
		},
		{
			name:         "content-length larger than body",
			raw:          "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello",
			expectedBody: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseHttpResponse([]byte(tt.raw), dummyReq)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBody, string(body))
		})
	}
}

// mockHttpRawEvent allows testing GetValidBuf with explicit buf_len values
// that differ from the actual buffer length (to test edge cases).
type mockHttpRawEvent struct {
	utils.StructEvent
	bufLen uint16
}

func (m *mockHttpRawEvent) GetBufLen() uint16 { return m.bufLen }

func TestGetValidBuf(t *testing.T) {
	httpData := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"

	t.Run("uses buf_len when set", func(t *testing.T) {
		event := &utils.StructEvent{Buf: []byte(httpData)}
		result := GetValidBuf(event)
		assert.Equal(t, len(httpData), len(result))
		assert.Equal(t, httpData, string(result))
	})

	t.Run("buf_len truncates garbage from ring buffer", func(t *testing.T) {
		// BPF buffer has valid data followed by a previous event's data (no null byte separator).
		previousEvent := "GET /old HTTP/1.1\r\nHost: old.com\r\n\r\n"
		buf := makeBPFBuffer(httpData + previousEvent)
		// With buf_len set correctly, only the real data is returned.
		event := &utils.StructEvent{Buf: buf[:len(httpData)]}
		result := GetValidBuf(event)
		assert.Equal(t, len(httpData), len(result))
		assert.Equal(t, httpData, string(result))

		// Verify the parsed request is clean.
		req, err := ParseHttpRequest(result)
		require.NoError(t, err)
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(body))
	})

	t.Run("buf_len < len(buf) truncates correctly", func(t *testing.T) {
		// Normal case: buf_len indicates valid data is shorter than buffer.
		buf := makeBPFBuffer(httpData)
		event := &mockHttpRawEvent{StructEvent: utils.StructEvent{Buf: buf}, bufLen: uint16(len(httpData))}
		result := GetValidBuf(event)
		assert.Equal(t, len(httpData), len(result), "should truncate to buf_len")
		assert.Equal(t, httpData, string(result))
	})

	t.Run("buf_len=0 returns full buffer (backward compatibility)", func(t *testing.T) {
		// When buf_len is 0 (error case), we fall back to returning the full buffer.
		buf := makeBPFBuffer(httpData)
		event := &mockHttpRawEvent{StructEvent: utils.StructEvent{Buf: buf}, bufLen: 0}
		result := GetValidBuf(event)
		assert.Equal(t, len(buf), len(result), "buf_len=0 should return full buffer")
	})

	t.Run("buf_len > len(buf) returns full buffer (safety)", func(t *testing.T) {
		// If buf_len exceeds buffer size, return full buffer as safety measure.
		buf := []byte(httpData)
		event := &mockHttpRawEvent{StructEvent: utils.StructEvent{Buf: buf}, bufLen: uint16(len(buf) + 100)}
		result := GetValidBuf(event)
		assert.Equal(t, len(buf), len(result), "buf_len > len(buf) should return full buffer")
	})

	t.Run("empty buffer", func(t *testing.T) {
		event := &mockHttpRawEvent{StructEvent: utils.StructEvent{Buf: []byte{}}, bufLen: 0}
		result := GetValidBuf(event)
		assert.Empty(t, result)
	})

	t.Run("buf_len equals buffer length", func(t *testing.T) {
		buf := []byte(httpData)
		event := &mockHttpRawEvent{StructEvent: utils.StructEvent{Buf: buf}, bufLen: uint16(len(buf))}
		result := GetValidBuf(event)
		assert.Equal(t, len(buf), len(result))
		assert.Equal(t, httpData, string(result))
	})
}
