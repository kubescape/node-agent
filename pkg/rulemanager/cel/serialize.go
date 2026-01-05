package cel

import (
	"encoding/json"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// CelSerializer is an interface that serializes events for CEL evaluation.
type CelSerializer interface {
	Serialize(event any) map[string]any
}

// CelEventSerializer is a default implementation of CelSerializer.
type CelEventSerializer struct{}

func (ces *CelEventSerializer) Serialize(event any) map[string]any {
	bytes, err := json.Marshal(event)
	if err != nil {
		logger.L().Error("Error marshaling event to JSON", helpers.Error(err))
		// Fallback or return an error map
		return map[string]any{"error": "serialization failed"}
	}

	var eventMap map[string]any
	if err := json.Unmarshal(bytes, &eventMap); err != nil {
		logger.L().Error("Error unmarshaling JSON to map", helpers.Error(err))
		// Fallback or return an error map
		return map[string]any{"error": "deserialization failed"}
	}

	if eventMap["Event"] != nil {
		if nestedEvent, ok := eventMap["Event"].(map[string]any); ok && nestedEvent["Event"] != nil {
			return map[string]any{"event": eventMap["Event"]}
		}
	}

	return map[string]any{
		"event": eventMap,
	}
}

var _ CelSerializer = (*CelEventSerializer)(nil)
