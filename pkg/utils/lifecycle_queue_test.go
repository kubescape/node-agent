package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLifecycleQueue(t *testing.T) {
	var queue LifecycleQueue
	unblock := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	independent := make(chan struct{})
	queue.Submit("one", func() { <-unblock; close(firstDone) })
	outOfOrder := make(chan struct{}, 1)
	queue.Submit("one", func() {
		select {
		case <-firstDone:
		default:
			outOfOrder <- struct{}{}
		}
		close(secondDone)
	})
	queue.Submit("two", func() { close(independent) })
	select {
	case <-independent:
	case <-time.After(time.Second):
		t.Fatal("unrelated container was blocked")
	}
	select {
	case <-secondDone:
		t.Fatal("cleanup overtook admission")
	default:
	}
	close(unblock)
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("queued callback did not finish")
	}
	select {
	case <-outOfOrder:
		t.Fatal("callbacks ran out of order")
	default:
	}
	require.Eventually(t, func() bool { queue.mu.Lock(); defer queue.mu.Unlock(); return len(queue.tails) == 0 }, time.Second, time.Millisecond)
}
