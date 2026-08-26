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

func TestNetworkCostEstimator_CoversEveryDeclaredFunction(t *testing.T) {
	est := &containerProfileNetworkCostEstimator{}
	for _, spec := range containerProfileNetworkFuncSpecs {
		assert.NotNil(t, est.EstimateCallCost("cp."+spec.name, "", nil, nil),
			"declared function cp.%s must have a cost estimate", spec.name)
	}
}

func TestLegacyCostEstimator_TranslatesPrefix(t *testing.T) {
	est := &legacyNetworkCostEstimator{inner: &containerProfileNetworkCostEstimator{}, legacyPrefix: "nn.", canonicalPrefix: "cp."}
	for _, spec := range containerProfileNetworkFuncSpecs {
		got := est.EstimateCallCost("nn."+spec.name, "", nil, nil)
		want := (&containerProfileNetworkCostEstimator{}).EstimateCallCost("cp."+spec.name, "", nil, nil)
		assert.Equal(t, want, got, "nn.%s must cost the same as cp.%s", spec.name, spec.name)
	}
	assert.Nil(t, est.EstimateCallCost("nn.does_not_exist", "", nil, nil))
}
