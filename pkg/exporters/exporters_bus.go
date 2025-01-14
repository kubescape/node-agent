package exporters

import (
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type ExportersConfig struct {
	StdoutExporter           *bool               `mapstructure:"stdoutExporter"`
	HTTPExporterConfig       *HTTPExporterConfig `mapstructure:"httpExporterConfig"`
	SyslogExporter           string              `mapstructure:"syslogExporterURL"`
	CsvRuleExporterPath      string              `mapstructure:"CsvRuleExporterPath"`
	CsvMalwareExporterPath   string              `mapstructure:"CsvMalwareExporterPath"`
	AlertManagerExporterUrls []string            `mapstructure:"alertManagerExporterUrls"`
}

// This file will contain the single point of contact for all exporters,
// it will be used by the engine to send alerts to all exporters.
type ExporterBus struct {
	// Exporters is a list of all exporters.
	exporters []Exporter
}

// InitExporters initializes all exporters.
func InitExporters(exportersConfig ExportersConfig, clusterName string, nodeName string, cloudMetadata *armotypes.CloudMetadata) *ExporterBus {
	var exporters []Exporter
	for _, url := range exportersConfig.AlertManagerExporterUrls {
		alertMan := InitAlertManagerExporter(url)
		if alertMan != nil {
			exporters = append(exporters, alertMan)
		}
	}
	stdoutExp := InitStdoutExporter(exportersConfig.StdoutExporter, cloudMetadata)
	if stdoutExp != nil {
		exporters = append(exporters, stdoutExp)
	}
	syslogExp := InitSyslogExporter(exportersConfig.SyslogExporter)
	if syslogExp != nil {
		exporters = append(exporters, syslogExp)
	}
	csvExp := InitCsvExporter(exportersConfig.CsvRuleExporterPath, exportersConfig.CsvMalwareExporterPath)
	if csvExp != nil {
		exporters = append(exporters, csvExp)
	}
	if exportersConfig.HTTPExporterConfig == nil {
		if httpURL := os.Getenv("HTTP_ENDPOINT_URL"); httpURL != "" {
			exportersConfig.HTTPExporterConfig = &HTTPExporterConfig{}
			exportersConfig.HTTPExporterConfig.URL = httpURL
		}
	}
	if exportersConfig.HTTPExporterConfig != nil {
		httpExporter, err := NewHTTPExporter(*exportersConfig.HTTPExporterConfig, clusterName, nodeName, cloudMetadata)
		if err == nil {
			exporters = append(exporters, httpExporter)
		} else {
			logger.L().Warning("InitExporters - failed to initialize http exporter", helpers.Error(err))
		}
	}

	if len(exporters) == 0 {
		logger.L().Fatal("InitExporters - no exporters were initialized")
	}
	logger.L().Info("exporters initialized")

	return &ExporterBus{exporters: exporters}
}

func (e *ExporterBus) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	for _, exporter := range e.exporters {
		exporter.SendRuleAlert(failedRule)
	}
}

func (e *ExporterBus) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	for _, exporter := range e.exporters {
		exporter.SendMalwareAlert(malwareResult)
	}
}
