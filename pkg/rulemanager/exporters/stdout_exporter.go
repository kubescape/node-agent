package exporters

import (
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/ruleengine"
	"os"

	log "github.com/sirupsen/logrus"
)

type StdoutExporter struct {
	logger *log.Logger
}

func InitStdoutExporter(useStdout *bool) *StdoutExporter {
	if useStdout == nil {
		useStdout = new(bool)
		*useStdout = os.Getenv("STDOUT_ENABLED") != "false"
	}
	if !*useStdout {
		return nil
	}

	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetOutput(os.Stderr)

	return &StdoutExporter{
		logger: logger,
	}
}

func (exporter *StdoutExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	exporter.logger.WithFields(log.Fields{
		"severity": failedRule.Priority(),
		"message":  failedRule.Error(),
		"event":    failedRule.Event(),
	}).Error(failedRule.Name())
}

func (exporter *StdoutExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	exporter.logger.WithFields(log.Fields{
		"severity":             10,
		"description":          malwareResult.GetDescription(),
		"md5hash":              malwareResult.GetMD5Hash(),
		"sha1hash":             malwareResult.GetSHA1Hash(),
		"sha256hash":           malwareResult.GetSHA256Hash(),
		"path":                 malwareResult.GetPath(),
		"size":                 malwareResult.GetSize(),
		"pod":                  malwareResult.GetPodName(),
		"namespace":            malwareResult.GetNamespace(),
		"container":            malwareResult.GetContainerName(),
		"containerID":          malwareResult.GetContainerID(),
		"isPartOfImage":        malwareResult.GetIsPartOfImage(),
		"containerImage":       malwareResult.GetContainerImage(),
		"containerImageDigest": malwareResult.GetContainerImageDigest(),
	}).Error(malwareResult.GetMalwareName())
}
