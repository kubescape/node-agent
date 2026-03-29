package v1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPSbomFailureReporter_Success(t *testing.T) {
	var capturedReport scanfailure.ScanFailureReport
	var capturedAPIKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get("X-API-KEY")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedReport)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := NewHTTPSbomFailureReporter(server.URL, "test-key")

	report := scanfailure.ScanFailureReport{
		CustomerGUID:  "test-account",
		ImageTag:      "nginx:1.25",
		FailureCase:   scanfailure.ScanFailureSBOMGeneration,
		FailureReason: scanfailure.ReasonImageTooLarge,
		Error:         "image size 4.2GB exceeds limit 2GB",
		Timestamp:     time.Now(),
		Workloads: []scanfailure.WorkloadIdentifier{{
			ClusterName:   "prod",
			Namespace:     "default",
			WorkloadKind:  "Deployment",
			WorkloadName:  "nginx",
			ContainerName: "web",
		}},
	}

	err := reporter.ReportSbomFailure(context.Background(), report)

	require.NoError(t, err)
	assert.Equal(t, "test-key", capturedAPIKey)
	assert.Equal(t, "test-account", capturedReport.CustomerGUID)
	assert.Equal(t, "nginx:1.25", capturedReport.ImageTag)
	assert.Equal(t, scanfailure.ReasonImageTooLarge, capturedReport.FailureReason)
	assert.Equal(t, "image size 4.2GB exceeds limit 2GB", capturedReport.Error)
	require.Len(t, capturedReport.Workloads, 1)
	assert.Equal(t, "web", capturedReport.Workloads[0].ContainerName)
}

func TestHTTPSbomFailureReporter_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	reporter := NewHTTPSbomFailureReporter(server.URL, "test-key")

	err := reporter.ReportSbomFailure(context.Background(), scanfailure.ScanFailureReport{
		CustomerGUID:  "test",
		FailureReason: scanfailure.ReasonSBOMGenerationFailed,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestHTTPSbomFailureReporter_NoAccessKey(t *testing.T) {
	var capturedAPIKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get("X-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := NewHTTPSbomFailureReporter(server.URL, "")

	err := reporter.ReportSbomFailure(context.Background(), scanfailure.ScanFailureReport{
		CustomerGUID:  "test",
		FailureReason: scanfailure.ReasonUnexpected,
	})

	require.NoError(t, err)
	assert.Empty(t, capturedAPIKey, "X-API-KEY should not be set when access key is empty")
}

func TestHTTPSbomFailureReporter_ConnectionError(t *testing.T) {
	reporter := NewHTTPSbomFailureReporter("http://localhost:1", "test-key")

	err := reporter.ReportSbomFailure(context.Background(), scanfailure.ScanFailureReport{
		CustomerGUID:  "test",
		FailureReason: scanfailure.ReasonSBOMGenerationFailed,
	})

	require.Error(t, err)
}
