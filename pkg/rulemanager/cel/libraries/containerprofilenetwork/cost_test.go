package containerprofilenetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkCostEstimator_NilForUnknownFunction(t *testing.T) {
	est := &containerProfileNetworkCostEstimator{}
	assert.Nil(t, est.EstimateCallCost("cp.does_not_exist", "", nil, nil),
		"unknown function must return nil (parity with the containerprofile estimator) so a zero cost never masks other estimates in the composite")
	assert.NotNil(t, est.EstimateCallCost("cp.was_address_in_egress", "", nil, nil),
		"known function must return a cost estimate")
}
