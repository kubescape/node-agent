package urldynamicdetector

import (
	"net/url"
	"strings"
)

func NewURLAnalyzer() *URLAnalyzer {
	return &URLAnalyzer{
		rootNodes: make(map[string]*SegmentNode),
	}
}
func (ua *URLAnalyzer) AnalyzeURL(urlString string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	hostname := parsedURL.Hostname()
	node, exists := ua.rootNodes[hostname]
	if !exists {
		node = &SegmentNode{
			SegmentName: hostname,
			Count:       0,
			Children:    make(map[string]*SegmentNode),
		}
		ua.rootNodes[hostname] = node
	}

	path := parsedURL.Path
	segments := strings.Split(strings.Trim(path, "/"), "/")

	return hostname + ua.processSegments(node, segments), nil
}

func (ua *URLAnalyzer) processSegments(node *SegmentNode, segments []string) string {
	resultPath := []string{}
	currentNode := node
	for _, segment := range segments {
		currentNode = ua.processSegment(currentNode, segment)
		ua.updateNodeStats(currentNode)
		resultPath = append(resultPath, currentNode.SegmentName)
	}
	return "/" + strings.Join(resultPath, "/")

}

func (ua *URLAnalyzer) processSegment(node *SegmentNode, segment string) *SegmentNode {

	switch {
	case segment == dynamicIdentifier:
		return ua.handleDynamicSegment(node)
	case KeyInMap(node.Children, segment) || node.IsNextDynamic():
		child, exists := node.Children[segment]
		return ua.handleExistingSegment(node, child, exists)
	default:
		return ua.handleNewSegment(node, segment)

	}
}

func (ua *URLAnalyzer) handleExistingSegment(node *SegmentNode, child *SegmentNode, exists bool) *SegmentNode {
	if exists {
		return child
	} else {
		return node.Children[dynamicIdentifier]
	}
}

func (ua *URLAnalyzer) handleNewSegment(node *SegmentNode, segment string) *SegmentNode {
	node.Count++
	newNode := &SegmentNode{
		SegmentName: segment,
		Count:       0,
		Children:    make(map[string]*SegmentNode),
	}
	node.Children[segment] = newNode
	return newNode
}

func (ua *URLAnalyzer) handleDynamicSegment(node *SegmentNode) *SegmentNode {
	if dynamicChild, exists := node.Children[dynamicIdentifier]; exists {
		return dynamicChild
	} else {
		return ua.createDynamicNode(node)
	}
}

func (ua *URLAnalyzer) createDynamicNode(node *SegmentNode) *SegmentNode {
	dynamicNode := &SegmentNode{
		SegmentName: dynamicIdentifier,
		Count:       0,
		Children:    make(map[string]*SegmentNode),
	}

	// Copy all existing children to the new dynamic node
	for _, child := range node.Children {
		shallowChildrensCopy(child, dynamicNode)
	}

	// Replace all children with the new dynamic node
	node.Children = map[string]*SegmentNode{
		dynamicIdentifier: dynamicNode,
	}

	return dynamicNode
}

func (ua *URLAnalyzer) updateNodeStats(node *SegmentNode) {
	if node.Count > theshold && !node.IsNextDynamic() {

		dynamicChild := &SegmentNode{
			SegmentName: dynamicIdentifier,
			Count:       0,
			Children:    make(map[string]*SegmentNode),
		}

		// Copy all descendants
		for _, child := range node.Children {
			shallowChildrensCopy(child, dynamicChild)
		}

		node.Children = map[string]*SegmentNode{
			dynamicIdentifier: dynamicChild,
		}
	}
}

func shallowChildrensCopy(src, dst *SegmentNode) {
	for segmentName := range src.Children {
		if !KeyInMap(dst.Children, segmentName) {
			dst.Children[segmentName] = src.Children[segmentName]
		}
	}
}

func KeyInMap[T any](TestMap map[string]T, key string) bool {
	_, ok := TestMap[key]
	return ok
}
