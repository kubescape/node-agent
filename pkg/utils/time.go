package utils

import (
	"math"
	"math/bits"
	"math/rand"
	"reflect"
	"runtime"
	"time"
)

// AddJitter adds jitter percent to the duration
func AddJitter(duration time.Duration, maxJitterPercentage int) time.Duration {
	if maxJitterPercentage <= 0 || duration <= 0 {
		return duration
	}
	// Integer arithmetic on the percentage truncated the jitter to zero for
	// any value under 100, so compute it on the duration itself. The product
	// is taken on 128 bits so it can't overflow, and the result is capped so
	// that duration + jitter fits in a time.Duration.
	headroom := uint64(math.MaxInt64 - int64(duration))
	maxJitter := headroom
	hi, lo := bits.Mul64(uint64(duration), uint64(maxJitterPercentage))
	if hi < 100 { // otherwise the quotient doesn't fit in 64 bits
		quo, _ := bits.Div64(hi, lo, 100)
		maxJitter = min(quo, headroom)
	}
	return duration + time.Duration(rand.Int63n(int64(maxJitter)+1))
}

// Jitter returns a random duration
func Jitter(duration *time.Duration, maxJitterPercentage float64) {
	if *duration == 0 {
		return
	}

	jitterFraction := maxJitterPercentage / 100.0
	jitterDuration := time.Duration(float64(*duration) * jitterFraction * (rand.Float64()*2 - 1))
	*duration += jitterDuration
}

// RandomDuration returns a duration between 1/2 max and max
func RandomDuration(max int, duration time.Duration) time.Duration {
	// we don't initialize the seed, so we will get the same sequence of random numbers every time
	mini := max / 2
	return time.Duration(rand.Intn(1+max-mini)+mini) * duration
}

func FuncName(i any) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
