package sbommanager

import (
	"context"

	"github.com/armosec/armoapi-go/scanfailure"
)

// SbomFailureReporter reports SBOM generation failures to the backend.
// The reporter sends a ScanFailureReport to POST /k8s/v2/scanFailure (careportreceiver),
// which feeds into the scan failure notification pipeline (event-ingester → UNS → Slack/Teams).
//
// Implementations:
//   - private-node-agent: HTTPSbomFailureReporter (uses existing backend URL + access key)
//   - upstream node-agent: nil (no reporting — backward compatible)
type SbomFailureReporter interface {
	ReportSbomFailure(ctx context.Context, report scanfailure.ScanFailureReport) error
}
