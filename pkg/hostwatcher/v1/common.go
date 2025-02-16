package hostwatcher

import (
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func isDroppedEvent(eventType types.EventType, message string) bool {
	return eventType != types.NORMAL &&
		eventType != types.DEBUG &&
		strings.Contains(message, "stop tracing container")
}
