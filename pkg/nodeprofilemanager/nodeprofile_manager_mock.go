package nodeprofilemanager

import (
	"context"
)

type NodeProfileManagerMock struct {
}

func NewNodeProfileManagerMock() *NodeProfileManagerMock {
	return &NodeProfileManagerMock{}
}

var _ NodeProfileManagerClient = (*NodeProfileManagerMock)(nil)

func (n *NodeProfileManagerMock) Start(_ context.Context) {
}
