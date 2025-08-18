package cel

import (
	"github.com/google/cel-go/checker"
)

// CompositeCostEstimator holds multiple estimators and queries them in order.
type CompositeCostEstimator struct {
	estimators []checker.CostEstimator
}

func NewCompositeCostEstimator(estimators ...checker.CostEstimator) checker.CostEstimator {
	return &CompositeCostEstimator{estimators: estimators}
}

// EstimateCallCost iterates through its estimators and returns the first non-nil estimate.
func (c *CompositeCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	for _, e := range c.estimators {
		if estimate := e.EstimateCallCost(function, overloadID, target, args); estimate != nil {
			return estimate
		}
	}
	return nil
}

// EstimateSize iterates through its estimators for a size estimate.
func (c *CompositeCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	for _, e := range c.estimators {
		if estimate := e.EstimateSize(element); estimate != nil {
			return estimate
		}
	}
	return nil
}
