package urldynamicdetector

import (
	"sync"
)

const dynamicIdentifier string = "<dynamic>"

const theshold = 100

type SegmentNode struct {
	SegmentName string
	Count       int
	Children    map[string]*SegmentNode
	mutex       sync.RWMutex
}

type URLAnalyzer struct {
	rootNodes map[string]*SegmentNode
}

func (sn *SegmentNode) IsNextDynamic() bool {
	_, exists := sn.Children[dynamicIdentifier]
	return exists
}
