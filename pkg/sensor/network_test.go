package sensor

import (
	"context"
	"testing"
)

func TestSenseOpenPorts(t *testing.T) {
	_, err := SenseOpenPorts(context.TODO())
	if err != nil {
		t.Errorf("%v", err)
	}
}
