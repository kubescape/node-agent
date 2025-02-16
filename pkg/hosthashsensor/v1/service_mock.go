package hosthashsensor

import "github.com/kubescape/node-agent/pkg/utils"

type HostHashSensorServiceMock struct {
}

func (s *HostHashSensorServiceMock) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	// noop
}

func (s *HostHashSensorServiceMock) Stop() error {
	return nil
}

func CreateHostHashSensorMock() *HostHashSensorServiceMock {
	return &HostHashSensorServiceMock{}
}
