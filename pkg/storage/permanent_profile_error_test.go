package storage

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type markedProfileError struct{ permanent bool }

func (e markedProfileError) Error() string   { return "storage rejected profile" }
func (e markedProfileError) Permanent() bool { return e.permanent }

func TestIsPermanentProfileError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil"},
		{name: "unknown", err: errors.New("unknown rejection")},
		{name: "true marker", err: markedProfileError{permanent: true}, want: true},
		{name: "wrapped true marker", err: fmt.Errorf("send: %w", markedProfileError{permanent: true}), want: true},
		{name: "false marker", err: markedProfileError{}},
		{name: "wrapped false marker", err: fmt.Errorf("send: %w", markedProfileError{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsPermanentProfileError(tc.err))
		})
	}
}
