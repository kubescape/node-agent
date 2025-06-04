package containerprofilemanager

import (
	"time"

	"github.com/google/uuid"
)

const (
	MaxSniffingTimeLabel          = "kubescape.io/max-sniffing-time"
	MaxWaitForSharedContainerData = 10 * time.Minute
)

// createUUID generates a new UUID string
func createUUID() string {
	return uuid.New().String()
}
