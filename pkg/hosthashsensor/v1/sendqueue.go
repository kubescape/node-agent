package hosthashsensor

import (
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hosthashsensor"
)

func createSendQueue(exporter exporters.Exporter) (*SendQueue, error) {
	return &SendQueue{
		queue:    make(chan hosthashsensor.FileHashResult),
		exporter: exporter,
	}, nil
}

func (s *SendQueue) PutOnSendQueue(finding hosthashsensor.FileHashResult) {
	if s.queue == nil {
		logger.L().Error("Send queue is nil")
		return
	}
	s.queue <- finding
}

func (s *SendQueue) Start() {
	if !s.started {
		s.started = true
		go s.mainLoop()
		logger.L().Info("Send queue started")
	} else {
		logger.L().Error("Send queue already started")
	}
}

func (s *SendQueue) Stop() {
	if s.started {
		s.started = false
		close(s.queue)
		logger.L().Info("Send queue stopped")
	} else {
		logger.L().Error("Send queue already stopped")
	}
}

func (s *SendQueue) mainLoop() {
	for {
		findings := make([]hosthashsensor.FileHashResult, 0, 100)
		timeout := time.After(60 * time.Second)

		// Keep collecting alerts until timeout or we hit max size
		collectingFindings := true
		for collectingFindings {
			select {
			case finding, ok := <-s.queue:
				if !ok {
					// Queue was closed, exit the loop
					collectingFindings = false
					break
				}
				findings = append(findings, finding)
				if len(findings) >= 100 {
					collectingFindings = false
				}
			case <-timeout:
				collectingFindings = false
			}
		}

		// Send collected findings if we have any
		if len(findings) > 0 {
			logger.L().Debug("Sending file hash alerts", helpers.Int("count", len(findings)))
			s.exporter.SendFileHashAlerts(findings)
		}
	}
}
