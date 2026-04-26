package sbommanager

import (
	"context"

	"github.com/armosec/armoapi-go/scanfailure"
)

type SbomFailureReporter interface {
	ReportSbomFailure(ctx context.Context, report scanfailure.ScanFailureReport) error
}
