package nodeprofilemanager

import (
	"golang.org/x/net/context"
)

type NodeProfileManagerClient interface {
	Start(ctx context.Context)
}
