package sandboxpolicy

import "testing"

func TestSeqCompare(t *testing.T) {
	for _, tc := range []struct {
		s, last Seq
		want    SeqOrder
	}{
		{Seq{1, 1}, Seq{1, 1}, SeqEqual},
		{Seq{0, 0}, Seq{0, 0}, SeqEqual},
		{Seq{2, 1}, Seq{1, 1}, SeqNewer},
		{Seq{1, 2}, Seq{1, 1}, SeqNewer},
		{Seq{2, 2}, Seq{1, 1}, SeqNewer},
		{Seq{1, 1}, Seq{2, 1}, SeqOlder},
		{Seq{1, 1}, Seq{1, 2}, SeqOlder},
		{Seq{1, 1}, Seq{2, 2}, SeqOlder},
		// One component greater, the other smaller: incomparable, in both
		// directions.
		{Seq{2, 1}, Seq{1, 2}, SeqIncomparable},
		{Seq{1, 2}, Seq{2, 1}, SeqIncomparable},
	} {
		if got := tc.s.Compare(tc.last); got != tc.want {
			t.Errorf("%+v against %+v: got %d, want %d", tc.s, tc.last, got, tc.want)
		}
	}
	if SeqOrder(0) != SeqIncomparable {
		t.Fatal("the zero order must be incomparable (not newer)")
	}
}

// epochScript returns the epochs in order, then repeats the last one.
func epochScript(epochs ...uint64) (func() uint64, *int) {
	calls := 0
	return func() uint64 {
		e := epochs[min(calls, len(epochs)-1)]
		calls++
		return e
	}, &calls
}

func TestCaptureInputs(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		epoch, _ := epochScript(5, 5)
		reads := 0
		got, e := CaptureInputs(epoch, func() int { reads++; return reads })
		if got != 1 || e != 5 || reads != 1 {
			t.Fatalf("got %d at %d after %d reads", got, e, reads)
		}
	})
	t.Run("one retry", func(t *testing.T) {
		// e1=5, the read races a bump (e2=6); the retry reads at 6, 6.
		epoch, calls := epochScript(5, 6, 6, 6)
		reads := 0
		got, e := CaptureInputs(epoch, func() int { reads++; return reads })
		if got != 2 || e != 6 || reads != 2 || *calls != 3 {
			t.Fatalf("got read %d at %d after %d reads, %d epoch reads", got, e, reads, *calls)
		}
	})
	t.Run("retry mismatches too", func(t *testing.T) {
		// Both reads race a bump: the second read is used with its own e1
		// (7), a lower bound; there is no third read.
		epoch, _ := epochScript(5, 6, 7, 8, 9)
		reads := 0
		got, e := CaptureInputs(epoch, func() int { reads++; return reads })
		if got != 2 || e != 7 || reads != 2 {
			t.Fatalf("got read %d at %d after %d reads", got, e, reads)
		}
	})
}
