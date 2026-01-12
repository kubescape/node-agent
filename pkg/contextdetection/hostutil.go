package contextdetection

import (
	"fmt"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// GetCurrentHostMntns reads the host's mount namespace ID from PID 1 (init process).
func GetCurrentHostMntns() (uint64, error) {
	mntns, err := containerutils.GetMntNs(1)
	if err != nil {
		logger.L().Error("failed to detect host mount namespace from PID 1",
			helpers.Error(err))
		return 0, fmt.Errorf("failed to get host mount namespace: %w", err)
	}

	return mntns, nil
}
