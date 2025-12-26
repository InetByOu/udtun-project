// common/utils.go
package common

import (
	"encoding/binary"
	"math/rand"
	"time"
)

func Uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

func BytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func RandomJitter(baseMs, maxJitterMs int) time.Duration {
	jitter := rand.Intn(maxJitterMs + 1)
	return time.Duration(baseMs+jitter) * time.Millisecond
}
