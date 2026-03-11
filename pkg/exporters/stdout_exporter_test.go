package exporters

import (
	"os"
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestInitStdoutExporter(t *testing.T) {
	// Test when useStdout is nil
	useStdout := new(bool)
	exporter := InitStdoutExporter(nil, nil)
	assert.NotNil(t, exporter)

	// Test when useStdout is true
	useStdout = new(bool)
	*useStdout = true
	exporter = InitStdoutExporter(useStdout, nil)
	assert.NotNil(t, exporter)
	assert.NotNil(t, exporter.logger)

	// Test when useStdout is false
	useStdout = new(bool)
	*useStdout = false
	exporter = InitStdoutExporter(useStdout, nil)
	assert.Nil(t, exporter)

	// Test when STDOUT_ENABLED environment variable is set to "false"
	os.Setenv("STDOUT_ENABLED", "false")
	exporter = InitStdoutExporter(nil, nil)
	assert.Nil(t, exporter)

	// Test when STDOUT_ENABLED environment variable is set to "true"
	os.Setenv("STDOUT_ENABLED", "true")
	exporter = InitStdoutExporter(nil, nil)
	assert.NotNil(t, exporter)
	assert.NotNil(t, exporter.logger)

	// Test when STDOUT_ENABLED environment variable is not set
	os.Unsetenv("STDOUT_ENABLED")
	exporter = InitStdoutExporter(nil, nil)
	assert.NotNil(t, exporter)
	assert.NotNil(t, exporter.logger)
}

func TestStdoutExporter_SendAlert(t *testing.T) {
	exporter := InitStdoutExporter(nil, nil)
	assert.NotNil(t, exporter)

	exporter.SendRuleAlert(&types.GenericRuleFailure{
		BaseRuntimeAlert: armotypes.BaseRuntimeAlert{
			AlertName: "testrule",
		},
		RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{
			ContainerID:   "testcontainerid",
			ContainerName: "testcontainer",
			Namespace:     "testnamespace",
			PodName:       "testpodname",
		},
		RuleAlert: armotypes.RuleAlert{
			RuleDescription: "Application profile is missing",
		},
	})
}

type MockFileHashResult struct {
}

func (m *MockFileHashResult) GetBasicRuntimeAlert() armotypes.BaseRuntimeAlert {
	return armotypes.BaseRuntimeAlert{
		AlertName: "testrule",
	}
}

func (m *MockFileHashResult) GetRuntimeProcessDetails() armotypes.ProcessTree {
	return armotypes.ProcessTree{
		ProcessTree: armotypes.Process{
			PID: 1,
		},
		ContainerID: "testcontainerid",
		UniqueID:    1,
	}
}

func (m *MockFileHashResult) GetMalwareRuntimeAlert() armotypes.MalwareAlert {
	return armotypes.MalwareAlert{
		MalwareDescription: "testmalware",
	}
}

func (m *MockFileHashResult) GetRuntimeAlertK8sDetails() armotypes.RuntimeAlertK8sDetails {
	return armotypes.RuntimeAlertK8sDetails{
		ContainerID:   "testcontainerid",
		ContainerName: "testcontainer",
		Namespace:     "testnamespace",
		PodName:       "testpodname",
		PodNamespace:  "testpodnamespace",
	}
}
