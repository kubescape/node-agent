package sensor

import (
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/kubescape/go-logger"
	// "github.com/kubescape/node-agent/sensor/internal/utils"
	"github.com/kubescape/host-scanner/sensor/internal/utils"

	"github.com/stretchr/testify/assert"
)

func Test_makeHostDirFilesInfo(t *testing.T) {
	utils.HostFileSystemDefaultLocation = "."
	fileInfos, err := makeHostDirFilesInfoVerbose(context.TODO(), "testdata/testmakehostfiles", true, nil, 0)
	assert.NoError(t, err)
	assert.Len(t, fileInfos, 4)

	// Test maxRecursionDepth
	// create a log file
	f, err := os.CreateTemp("", "log-*")
	assert.NoError(t, err)
	defer os.Remove(f.Name()) // clean up
	logger.InitLogger("pretty")
	logger.L().SetWriter(f)

	// test
	fileInfos, err = makeHostDirFilesInfoVerbose(context.TODO(), "testdata/testmakehostfiles", true, nil, maxRecursionDepth-1)
	assert.NoError(t, err)
	assert.Len(t, fileInfos, 3)

	// check log output for error message
	data, err := os.ReadFile(f.Name())
	assert.NoError(t, err)
	re := regexp.MustCompile("max recursion depth exceeded")
	assert.Len(t, re.FindAll(data, -1), 1)
}
