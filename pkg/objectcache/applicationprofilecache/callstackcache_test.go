package applicationprofilecache

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// Helper function to build unified call stacks for testing
func buildUnifiedStack(callID string, paths [][]struct{ fileID, lineno string }) v1beta1.IdentifiedCallStack {
	stack := v1beta1.IdentifiedCallStack{
		CallID: v1beta1.CallID(callID),
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame:    v1beta1.StackFrame{},
				Children: make([]v1beta1.CallStackNode, 0),
			},
		},
	}

	if len(paths) == 0 || len(paths[0]) == 0 {
		return stack
	}

	fmt.Printf("Building stack with %d paths\n", len(paths))
	for i, path := range paths {
		fmt.Printf("Path %d: ", i)
		for _, f := range path {
			fmt.Printf("{%s %s} ", f.fileID, f.lineno)
		}
		fmt.Println()
	}

	// Create and add the first node
	firstNode := v1beta1.CallStackNode{
		Frame: v1beta1.StackFrame{
			FileID: paths[0][0].fileID,
			Lineno: paths[0][0].lineno,
		},
		Children: make([]v1beta1.CallStackNode, 0),
	}
	stack.CallStack.Root.Children = append(stack.CallStack.Root.Children, firstNode)
	fmt.Printf("Created first node: {%s %s}\n", firstNode.Frame.FileID, firstNode.Frame.Lineno)

	// For each path
	for pathIdx, path := range paths {
		fmt.Printf("\nProcessing path %d:\n", pathIdx)
		current := &stack.CallStack.Root.Children[0] // Start at the first real node
		fmt.Printf("Starting at node: {%s %s}\n", current.Frame.FileID, current.Frame.Lineno)

		// Skip the first frame since we already added it
		for frameIdx := 1; frameIdx < len(path); frameIdx++ {
			frame := path[frameIdx]
			fmt.Printf("Processing frame {%s %s}\n", frame.fileID, frame.lineno)

			// Check if this frame already exists in children
			found := false
			for i := range current.Children {
				if current.Children[i].Frame.FileID == frame.fileID &&
					current.Children[i].Frame.Lineno == frame.lineno {
					current = &current.Children[i]
					found = true
					fmt.Printf("Found existing node for frame\n")
					break
				}
			}

			// If not found, add new node
			if !found {
				newNode := v1beta1.CallStackNode{
					Frame: v1beta1.StackFrame{
						FileID: frame.fileID,
						Lineno: frame.lineno,
					},
					Children: make([]v1beta1.CallStackNode, 0),
				}
				current.Children = append(current.Children, newNode)
				current = &current.Children[len(current.Children)-1]
				fmt.Printf("Created new node for frame\n")
			}

			fmt.Printf("Current node now: {%s %s} with %d children\n",
				current.Frame.FileID, current.Frame.Lineno, len(current.Children))
		}
	}

	// Debug print final tree structure
	fmt.Println("\nFinal tree structure:")
	var printNode func(node v1beta1.CallStackNode, depth int)
	printNode = func(node v1beta1.CallStackNode, depth int) {
		indent := strings.Repeat("  ", depth)
		fmt.Printf("%s{%s %s} (children: %d)\n",
			indent, node.Frame.FileID, node.Frame.Lineno, len(node.Children))
		for _, child := range node.Children {
			printNode(child, depth+1)
		}
	}
	for _, child := range stack.CallStack.Root.Children {
		printNode(child, 0)
	}

	return stack
}

func TestCallStackSearchTreeBranching(t *testing.T) {
	tree := NewCallStackSearchTree()

	// Create a branching stack similar to the real example
	branchingStack := buildUnifiedStack("test1", [][]struct{ fileID, lineno string }{
		{
			{"10425069705252389217", "645761"},
			{"10425069705252389217", "653231"},
			{"2918313636494991837", "867979"},
			{"4298936378959959569", "390324"},
		},
		{
			{"10425069705252389217", "645761"},
			{"10425069705252389217", "653231"},
			{"2918313636494991837", "867979"},
			{"0", "4012"},
		},
	})

	tree.AddCallStack(branchingStack)

	// Debug print the stored tree before verification
	fmt.Println("\nStored tree before verification:")
	printBiNode(tree.Roots["test1"], 0)

	fmt.Println("\nStarting verification:")

	// Start verification
	root := tree.Roots["test1"]
	fmt.Printf("Root frame: {%s %s}\n", root.Frame.FileID, root.Frame.Lineno)

	current := root
	expectedFrames := []struct{ fileID, lineno string }{
		{"10425069705252389217", "645761"},
		{"10425069705252389217", "653231"},
		{"2918313636494991837", "867979"},
	}

	for i := 0; i < len(expectedFrames); i++ {
		expected := expectedFrames[i]
		fmt.Printf("\nVerifying depth %d:\n", i)
		fmt.Printf("Current frame: {%s %s}\n", current.Frame.FileID, current.Frame.Lineno)
		fmt.Printf("Expected frame: {%s %s}\n", expected.fileID, expected.lineno)
		fmt.Printf("Current has %d children\n", len(current.Children))

		if !framesEqual(current.Frame, v1beta1.StackFrame{FileID: expected.fileID, Lineno: expected.lineno}) {
			t.Errorf("At depth %d, unexpected frame: got {%s %s}, expected {%s %s}",
				i, current.Frame.FileID, current.Frame.Lineno, expected.fileID, expected.lineno)
		}
		if i < len(expectedFrames)-1 {
			if len(current.Children) != 1 {
				t.Errorf("Expected 1 child at common path depth %d, got %d", i, len(current.Children))
				return
			}
			current = current.Children[0]
		}
	}

	// At last common node (867979), verify branching
	fmt.Printf("\nVerifying branching at 867979 node:\n")
	fmt.Printf("Current frame: {%s %s}\n", current.Frame.FileID, current.Frame.Lineno)
	fmt.Printf("Has %d children\n", len(current.Children))

	if len(current.Children) != 2 {
		t.Errorf("Expected 2 branches at node 867979, got %d", len(current.Children))
		return
	}

	// Verify both branch endpoints exist
	foundBranch1 := false
	foundBranch2 := false
	for _, child := range current.Children {
		fmt.Printf("Checking child: {%s %s}\n", child.Frame.FileID, child.Frame.Lineno)
		if framesEqual(child.Frame, v1beta1.StackFrame{FileID: "4298936378959959569", Lineno: "390324"}) {
			foundBranch1 = true
		}
		if framesEqual(child.Frame, v1beta1.StackFrame{FileID: "0", Lineno: "4012"}) {
			foundBranch2 = true
		}
	}

	if !foundBranch1 {
		t.Error("Missing branch with 390324")
	}
	if !foundBranch2 {
		t.Error("Missing branch with 4012")
	}
}

func printBiNode(node *BidirectionalNode, depth int) {
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s{%s %s} (children: %d)",
		indent, node.Frame.FileID, node.Frame.Lineno, len(node.Children))
	if node.Parent != nil {
		fmt.Printf(" [parent: {%s %s}]",
			node.Parent.Frame.FileID, node.Parent.Frame.Lineno)
	}
	fmt.Println()
	for _, child := range node.Children {
		printBiNode(child, depth+1)
	}
}

func TestCallStackSearchTreeBasic(t *testing.T) {
	tree := NewCallStackSearchTree()

	// Test with simple linear path
	simpleStack := buildUnifiedStack("test1", [][]struct{ fileID, lineno string }{
		{
			{"1", "1"},
			{"2", "1"},
			{"3", "1"},
		},
	})

	tree.AddCallStack(simpleStack)

	// Verify path storage
	paths := tree.PathsByCallID["test1"]
	if len(paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(paths))
	}

	// Verify trie storage
	expectedKey := "1:1/2:1/3:1"
	value := tree.ForwardTrie.Get(expectedKey)
	if value == nil {
		t.Error("Path not found in trie")
	}

	// Verify bidirectional tree
	root := tree.Roots["test1"]
	if root == nil {
		t.Fatal("Root node not found")
	}

	current := root
	expectedFrames := []v1beta1.StackFrame{
		{FileID: "1", Lineno: "1"},
		{FileID: "2", Lineno: "1"},
		{FileID: "3", Lineno: "1"},
	}

	for i, expected := range expectedFrames {
		if !framesEqual(current.Frame, expected) {
			t.Errorf("At depth %d, expected frame %v, got %v", i, expected, current.Frame)
		}
		if i < len(expectedFrames)-1 {
			if len(current.Children) != 1 {
				t.Errorf("Expected 1 child at depth %d, got %d", i, len(current.Children))
				break
			}
			current = current.Children[0]
		}
	}
}

func TestCallStackSearchTreeWithSpecialFrame(t *testing.T) {
	tree := NewCallStackSearchTree()

	// Test with the [0:4012] case from the real data
	stack := buildUnifiedStack("test1", [][]struct{ fileID, lineno string }{
		{
			{"10425069705252389217", "645761"},
			{"10425069705252389217", "653231"},
			{"2918313636494991837", "867979"},
			{"0", "4012"},
		},
	})

	tree.AddCallStack(stack)

	// Verify the path is stored correctly
	paths := tree.PathsByCallID["test1"]
	if len(paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(paths))
	}

	// Verify path with special frame exists in trie
	expectedKey := "10425069705252389217:645761/10425069705252389217:653231/2918313636494991837:867979/0:4012"
	if value := tree.ForwardTrie.Get(expectedKey); value == nil {
		t.Error("Special frame path not found in trie")
	}

	// Verify the node structure
	root := tree.Roots["test1"]
	if root == nil {
		t.Fatal("Root node not found")
	}

	// Navigate to the special frame
	current := root
	frames := []struct{ fileID, lineno string }{
		{"10425069705252389217", "645761"},
		{"10425069705252389217", "653231"},
		{"2918313636494991837", "867979"},
		{"0", "4012"},
	}

	for i, expectedFrame := range frames {
		if !framesEqual(current.Frame, v1beta1.StackFrame{
			FileID: expectedFrame.fileID,
			Lineno: expectedFrame.lineno,
		}) {
			t.Errorf("Unexpected frame at depth %d", i)
		}

		if i < len(frames)-1 {
			if len(current.Children) != 1 {
				t.Errorf("Expected single child at depth %d, got %d", i, len(current.Children))
				return
			}
			current = current.Children[0]
		}
	}

	// Verify parent references
	for current.Parent != nil {
		current = current.Parent
	}
	if current != root {
		t.Error("Parent chain doesn't lead back to root")
	}
}

func TestCallStackSearchTreeEmpty(t *testing.T) {
	tree := NewCallStackSearchTree()

	// Test with empty stack
	emptyStack := buildUnifiedStack("test1", [][]struct{ fileID, lineno string }{{}})
	tree.AddCallStack(emptyStack)

	// Verify empty path handling
	paths := tree.PathsByCallID["test1"]
	if len(paths) != 0 {
		t.Errorf("Expected 0 paths for empty stack, got %d", len(paths))
	}

	// Verify root handling
	if root := tree.Roots["test1"]; root != nil {
		t.Error("Expected nil root for empty stack")
	}
}

func TestCallStackSearchTreeMultipleCallIDs(t *testing.T) {
	tree := NewCallStackSearchTree()

	// Add stacks with different CallIDs
	stack1 := buildUnifiedStack("id1", [][]struct{ fileID, lineno string }{
		{
			{"1", "1"},
			{"2", "1"},
		},
	})
	stack2 := buildUnifiedStack("id2", [][]struct{ fileID, lineno string }{
		{
			{"1", "1"},
			{"2", "2"},
		},
	})

	tree.AddCallStack(stack1)
	tree.AddCallStack(stack2)

	// Verify separate storage by CallID
	if len(tree.PathsByCallID) != 2 {
		t.Errorf("Expected 2 CallIDs, got %d", len(tree.PathsByCallID))
	}

	// Verify paths for each CallID
	paths1 := tree.PathsByCallID["id1"]
	paths2 := tree.PathsByCallID["id2"]
	if len(paths1) != 1 || len(paths2) != 1 {
		t.Error("Wrong number of paths per CallID")
	}

	// Verify separate root nodes with correct structures
	root1 := tree.Roots["id1"]
	root2 := tree.Roots["id2"]
	if root1 == nil || root2 == nil {
		t.Fatal("Missing root nodes")
	}

	if !framesEqual(root1.Children[0].Frame, v1beta1.StackFrame{FileID: "2", Lineno: "1"}) {
		t.Error("Incorrect frame in first stack")
	}
	if !framesEqual(root2.Children[0].Frame, v1beta1.StackFrame{FileID: "2", Lineno: "2"}) {
		t.Error("Incorrect frame in second stack")
	}
}
