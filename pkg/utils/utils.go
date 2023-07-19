package utils

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func Between(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, a)
	if posFirst == -1 {
		return ""
	}
	substr := value[posFirst+len(a):]
	posLast := strings.Index(substr, b) + posFirst + len(a)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

func After(value string, a string) string {
	// Get substring after a string.
	pos := strings.LastIndex(value, a)
	if pos == -1 {
		return ""
	}
	adjustedPos := pos + len(a)
	if adjustedPos >= len(value) {
		return ""
	}
	return value[adjustedPos:]
}

func CurrentDir() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}

func CreateK8sContainerID(namespaceName string, podName string, containerName string) string {
	return fmt.Sprintf("%s/%s/%s", namespaceName, podName, containerName)
}

// RandomSleep sleeps between min and max seconds
func RandomSleep(min, max int) {
	// we don't initialize the seed, so we will get the same sequence of random numbers every time
	randomDuration := time.Duration(rand.Intn(max+1-min)+min) * time.Second
	time.Sleep(randomDuration)
}
