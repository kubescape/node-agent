package context

import (
	"context"
	"net/url"
	"os"
	"sniffer/pkg/config"

	"github.com/kubescape/go-logger"
)

const (
	releaseBuildTagEnvironmentVariable = "RELEASE"
)

type BackgroundContext struct {
	ctx  context.Context
}

var backgroundContext BackgroundContext

func init() {
	backgroundContext = BackgroundContext{
		ctx: context.Background(),
	}
}

func SetBackgroundContext() {
	ctx := logger.InitOtel("nodeagent",
		os.Getenv(releaseBuildTagEnvironmentVariable),
		config.GetConfigurationConfigContext().GetAccountID(),
		config.GetConfigurationConfigContext().GetClusterName(),
		url.URL{Host: config.GetConfigurationConfigContext().GetBackgroundContextURL()})
	backgroundContext.ctx = ctx
}

func GetBackgroundContext() context.Context {
	return backgroundContext.ctx
}