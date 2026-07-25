package main

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type DigestAuth struct {
	mu         sync.Mutex
	nonce      string
	nonceCount int64
	realm      string
}

func NewDigestAuth(realm string) *DigestAuth {
	return &DigestAuth{nonce: "abc123", realm: realm}
}

func (d *DigestAuth) NextNonceCount() int64 {
	return atomic.AddInt64(&d.nonceCount, 1)
}

func (d *DigestAuth) NonceCount() int64 {
	return atomic.LoadInt64(&d.nonceCount)
}

func (d *DigestAuth) GenerateAuthorization(username, password, method, uri string) string {
	nc := d.NextNonceCount()
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", nc=%08x`,
		username, d.realm, d.nonce, uri, nc)
}

func (d *DigestAuth) Request(id int, username, password, method, uri string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()
	header := d.GenerateAuthorization(username, password, method, uri)
	results <- fmt.Sprintf("Request %d: nc=%d header=%s", id, d.NonceCount(), header[:40]+"...")
}

func main() {
	auth := NewDigestAuth("api@example.com")
	var wg sync.WaitGroup
	results := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go auth.Request(i, "user", "pass", "GET", "/api/data", &wg, results)
	}
	wg.Wait()
	close(results)
	for r := range results {
		fmt.Println(r)
	}
	nc := auth.NonceCount()
	pass := nc == 20
	fmt.Printf("Total nonce count: %d - %s\n", nc,
		map[bool]string{true: "PASS", false: "FAIL"}[pass])
	fmt.Println("Digest auth race condition fixed with atomic operations")
}
