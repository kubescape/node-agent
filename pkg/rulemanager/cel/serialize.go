package cel

import (
	"github.com/fatih/structs"
)

// CelSerializer is an interface that serializes events for CEL evaluation.
type CelSerializer interface {
	Serialize(event any) map[string]any
}

// CelEventSerializer is a default implementation of CelSerializer.
type CelEventSerializer struct{}

func (ces *CelEventSerializer) Serialize(event any) map[string]any {
	eventMap := structs.Map(event)

	if eventMap["Event"] != nil {
		if event, ok := eventMap["Event"].(map[string]any); ok && event["Event"] != nil {
			return map[string]any{
				"event": eventMap["Event"],
			}
		}
	}

	return map[string]any{
		"event": eventMap,
	}
}

var _ CelSerializer = (*CelEventSerializer)(nil)
