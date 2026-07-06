package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// fakeSource is a minimal watch.Interface whose ResultChan is driven by the test.
type fakeSource struct {
	ch      chan watch.Event
	stopped bool
}

func newFakeSource() *fakeSource { return &fakeSource{ch: make(chan watch.Event)} }

func (f *fakeSource) Stop()                          { f.stopped = true; close(f.ch) }
func (f *fakeSource) ResultChan() <-chan watch.Event { return f.ch }

// When the consumer never reads ResultChan(), a pending forward must not pin the
// run() goroutine forever: Stop() must unblock it and close the result channel.
func TestConvertingWatch_StopUnblocksPendingSend(t *testing.T) {
	src := newFakeSource()
	cw := newConvertingWatch(src)

	// Push an error event; run() will block trying to forward it onto the
	// unbuffered result channel because we never read from ResultChan().
	src.ch <- watch.Event{Type: watch.Error, Object: &metav1.Status{Code: 410}}

	// Give run() a moment to park on the send.
	time.Sleep(20 * time.Millisecond)

	cw.Stop()

	// After Stop(), run() must exit and close the result channel.
	select {
	case _, ok := <-cw.ResultChan():
		assert.False(t, ok, "result channel should be closed after Stop()")
	case <-time.After(time.Second):
		t.Fatal("run() goroutine leaked: result channel not closed after Stop()")
	}
}

func TestConvertingWatch_StopIsIdempotent(t *testing.T) {
	src := newFakeSource()
	cw := newConvertingWatch(src)
	cw.Stop()
	assert.NotPanics(t, func() { cw.Stop() }, "second Stop() must not panic")
}
