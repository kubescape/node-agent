package utils

import (
	"math/rand"
	"reflect"
	"runtime"
	"time"
)

// AddJitter adds jitter percent to the duration
func AddJitter(duration time.Duration, maxJitterPercentage int) time.Duration {
	if maxJitterPercentage == 0 {
		return duration
	}
	jitter := 1 + rand.Intn(maxJitterPercentage)/100
	return duration * time.Duration(jitter)
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

func FuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
