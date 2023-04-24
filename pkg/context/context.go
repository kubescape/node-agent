package context

import (
	"context"
	"net/url"
	"os"
	"sniffer/pkg/config"

	"github.com/kubescape/go-logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const (
	releaseBuildTagEnvironmentVariable = "RELEASE"
)

type BackgroundContext struct {
	ctx  context.Context
	span trace.Span
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
	setMainSpan(ctx)
}

func setMainSpan(context context.Context) {
	ctx, span := otel.Tracer("").Start(context, "mainSpan")
	backgroundContext.ctx = ctx
	backgroundContext.span = span
}

func GetBackgroundContext() context.Context {
	return backgroundContext.ctx
}

func GetMainSpan() trace.Span {
	return backgroundContext.span
}
