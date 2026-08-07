package main

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// DigestAuth with thread-safe nonce counting.
// The bug: concurrent requests cause race condition in nonce count.
// Fix: Use atomic counter for nonce and mutex for auth state.
type DigestAuth struct {
	mu     sync.Mutex
	nonce  uint64
}

func NewDigestAuth() *DigestAuth {
	return &DigestAuth{}
}

func (d *DigestAuth) NextNonce() string {
	n := atomic.AddUint64(&d.nonce, 1)
	return fmt.Sprintf("nonce-%d", n)
}

func main() {
	auth := NewDigestAuth()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = auth.NextNonce() }()
	}
	wg.Wait()
	fmt.Printf("Final nonce count: %d (expected 10)\n", auth.nonce)
}
