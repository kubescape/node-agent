package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/sbommanager"
)

var _ sbommanager.SbomFailureReporter = (*HTTPSbomFailureReporter)(nil)

// HTTPSbomFailureReporter sends scan failure reports to careportreceiver via HTTP POST.
// Uses the same endpoint and auth as kubevuln: POST /k8s/v2/scanFailure with X-API-KEY header.
type HTTPSbomFailureReporter struct {
	eventReceiverURL string
	accessKey        string
	httpClient       *http.Client
}

// NewHTTPSbomFailureReporter creates a reporter that POSTs to the given event receiver URL.
// eventReceiverURL is the base URL (e.g., "http://event-receiver-http.kubescape.svc.cluster.local:8080").
// accessKey is the cluster access key for the X-API-KEY header.
func NewHTTPSbomFailureReporter(eventReceiverURL, accessKey string) *HTTPSbomFailureReporter {
	return &HTTPSbomFailureReporter{
		eventReceiverURL: eventReceiverURL,
		accessKey:        accessKey,
		httpClient:       &http.Client{},
	}
}

func (r *HTTPSbomFailureReporter) ReportSbomFailure(ctx context.Context, report scanfailure.ScanFailureReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal scan failure report: %w", err)
	}

	url := fmt.Sprintf("%s/k8s/v2/scanFailure", r.eventReceiverURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.accessKey != "" {
		req.Header.Set("X-API-KEY", r.accessKey)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to send scan failure report",
			helpers.Error(err))
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("scan failure report returned HTTP %d", resp.StatusCode)
	}
	return nil
}
