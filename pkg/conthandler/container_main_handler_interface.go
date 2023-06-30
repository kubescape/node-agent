package conthandler

import "context"

type ContainerMainHandlerClient interface {
	StartMainHandler(ctx context.Context) error
	StopMainHandler()
}
