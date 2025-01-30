package callstackcache

import (
	"strings"

	"github.com/dghubble/trie"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// BidirectionalNode extends the call stack node with parent reference
type BidirectionalNode struct {
	Frame    v1beta1.StackFrame
	Parent   *BidirectionalNode
	Children []*BidirectionalNode
}

// CallStackSearchTree provides efficient searching and comparison of call stacks
type CallStackSearchTree struct {
	// Store forward paths in trie for prefix matching
	ForwardTrie *trie.PathTrie
	// Store complete paths mapped by CallID for quick lookup
	PathsByCallID map[v1beta1.CallID][][]v1beta1.StackFrame
	// Store root nodes for bidirectional traversal
	Roots map[v1beta1.CallID]*BidirectionalNode
}

func NewCallStackSearchTree() *CallStackSearchTree {
	return &CallStackSearchTree{
		ForwardTrie:   trie.NewPathTrie(),
		PathsByCallID: make(map[v1beta1.CallID][][]v1beta1.StackFrame),
		Roots:         make(map[v1beta1.CallID]*BidirectionalNode),
	}
}

// AddCallStack adds a new identified call stack to the search tree
func (t *CallStackSearchTree) AddCallStack(stack v1beta1.IdentifiedCallStack) {
	// Get all paths from the call stack
	paths := getCallStackPaths(stack.CallStack)
	if len(paths) == 0 {
		return
	}

	// First create root from first path
	firstPath := paths[0]
	firstFrames := make([]v1beta1.StackFrame, len(firstPath))
	for i, node := range firstPath {
		firstFrames[i] = node.Frame
	}

	root := t.buildBidirectionalTree(firstFrames)
	t.Roots[stack.CallID] = root

	// Store paths for this CallID
	t.PathsByCallID[stack.CallID] = make([][]v1beta1.StackFrame, 0)
	t.PathsByCallID[stack.CallID] = append(t.PathsByCallID[stack.CallID], firstFrames)

	// Add first path to trie
	key := pathToKey(firstFrames)
	t.ForwardTrie.Put(key, firstFrames)

	// Process remaining paths
	for i := 1; i < len(paths); i++ {
		path := paths[i]
		frames := make([]v1beta1.StackFrame, len(path))
		for j, node := range path {
			frames[j] = node.Frame
		}

		// Add to paths by CallID
		t.PathsByCallID[stack.CallID] = append(t.PathsByCallID[stack.CallID], frames)

		// Add to trie
		key = pathToKey(frames)
		t.ForwardTrie.Put(key, frames)

		// Merge into bidirectional tree
		current := root

		for j := 1; j < len(frames); j++ { // Start from 1 since we know root matches
			frame := frames[j]

			// Try to find matching child
			var found *BidirectionalNode
			for _, child := range current.Children {
				if framesEqual(child.Frame, frame) {
					found = child
					break
				}
			}

			// If no matching child found, create new node
			if found == nil {
				newNode := &BidirectionalNode{
					Frame:    frame,
					Parent:   current,
					Children: make([]*BidirectionalNode, 0),
				}
				current.Children = append(current.Children, newNode)
				current = newNode
			} else {
				current = found
			}
		}
	}
}

// buildBidirectionalTree creates a tree with parent references
func (t *CallStackSearchTree) buildBidirectionalTree(frames []v1beta1.StackFrame) *BidirectionalNode {
	if len(frames) == 0 {
		return nil
	}

	root := &BidirectionalNode{
		Frame:    frames[0],
		Children: make([]*BidirectionalNode, 0),
	}

	current := root
	for i := 1; i < len(frames); i++ {
		node := &BidirectionalNode{
			Frame:    frames[i],
			Parent:   current,
			Children: make([]*BidirectionalNode, 0),
		}
		current.Children = append(current.Children, node)
		current = node
	}

	return root
}

// getCallStackPaths returns all complete paths in a call stack
func getCallStackPaths(cs v1beta1.CallStack) [][]v1beta1.CallStackNode {
	var paths [][]v1beta1.CallStackNode
	var traverse func(node v1beta1.CallStackNode, currentPath []v1beta1.CallStackNode)

	traverse = func(node v1beta1.CallStackNode, currentPath []v1beta1.CallStackNode) {
		path := append([]v1beta1.CallStackNode{}, currentPath...)
		path = append(path, node)

		if len(node.Children) == 0 {
			paths = append(paths, path)
			return
		}
		for _, child := range node.Children {
			traverse(child, path)
		}
	}

	if isEmptyFrame(cs.Root.Frame) {
		for _, child := range cs.Root.Children {
			traverse(child, nil)
		}
	} else {
		traverse(cs.Root, nil)
	}

	return paths
}

// isEmptyFrame checks if a StackFrame is empty
func isEmptyFrame(frame v1beta1.StackFrame) bool {
	return frame.FileID == "" && frame.Lineno == ""
}

// Helper functions
func pathToKey(frames []v1beta1.StackFrame) string {
	parts := make([]string, len(frames))
	for i, frame := range frames {
		parts[i] = frameKey(frame)
	}
	return strings.Join(parts, "/")
}

// frameKey returns a unique key for a stack frame
func frameKey(frame v1beta1.StackFrame) string {
	return frame.FileID + ":" + frame.Lineno
}

// framesEqual checks if two call stacks are equal
func framesEqual(a, b v1beta1.StackFrame) bool {
	return a.FileID == b.FileID && a.Lineno == b.Lineno
}
