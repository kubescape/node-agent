package hostmanager

import "context"

type HostManagerClient interface {
	Start(ctx context.Context)
}
