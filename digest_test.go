// Copyright (c) 2024 Sonja & Cliff
// Licensed under the MIT License.

package resty

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"
)

// strictDigestServer is a mock HTTP server that implements Digest Access
// Authentication and strictly validates the nonce count (nc). It rejects
// any request whose nc value has already been seen for the active nonce,
// simulating a server that enforces unique, monotonically increasing nc.
type strictDigestServer struct {
	mu       sync.Mutex
	username string
	password string
	realm    string
	nonce    string
	seenNCs  map[int]bool
}

func newStrictDigestServer() *strictDigestServer {
	return &strictDigestServer{
		username: "testuser",
		password: "testpass",
		realm:    "testrealm@host.com",
		nonce:    "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		seenNCs:  make(map[int]bool),
	}
}

func (s *strictDigestServer) challenge() string {
	return fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth", algorithm=MD5`,
		s.realm, s.nonce)
}

func (s *strictDigestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	// No auth header → send the digest challenge.
	if auth == "" {
		w.Header().Set("WWW-Authenticate", s.challenge())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Parse the Authorization header.
	params := parseAuthParams(auth)
	ncStr := params["nc"]
	if ncStr == "" {
		w.Header().Set("WWW-Authenticate", s.challenge())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ncVal, err := strconv.ParseInt(ncStr, 16, 64)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	nc := int(ncVal)

	// Strict nc validation: reject duplicate nc values.
	// With the bug (all goroutines send nc=1), 49 of 50 requests would
	// be rejected here. With the fix, each goroutine gets a unique nc.
	s.mu.Lock()
	if s.seenNCs[nc] {
		s.mu.Unlock()
		w.Header().Set("WWW-Authenticate", s.challenge())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.seenNCs[nc] = true
	s.mu.Unlock()

	// Validate the response hash.
	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", s.username, s.realm, s.password))
	ha2 := md5hex(fmt.Sprintf("%s:%s", r.Method, r.URL.RequestURI()))
	expected := md5hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		ha1, s.nonce, ncStr, params["cnonce"], "auth", ha2))

	if params["response"] != expected {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

var authParamRe = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^,]+))`)

// parseAuthParams extracts key=value pairs from a Digest Authorization header.
func parseAuthParams(auth string) map[string]string {
	params := make(map[string]string)
	for _, m := range authParamRe.FindAllStringSubmatch(auth, -1) {
		key, val := m[1], m[2]
		if val == "" {
			val = m[3]
		}
		params[key] = val
	}
	return params
}

// TestDigestAuth_Basic verifies that a single digest-authenticated request
// succeeds against the mock server.
func TestDigestAuth_Basic(t *testing.T) {
	server := newStrictDigestServer()
	ts := httptest.NewServer(server)
	defer ts.Close()

	client := New()
	client.SetDigestAuth(server.username, server.password)

	resp, err := client.R().Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", resp.StatusCode, resp.Body)
	}
}

// TestDigestAuth_Concurrency verifies that 50 concurrent requests using a
// single shared Client all succeed. This exercises the thread-safety of the
// digest state (nc, cnonce) under concurrent load.
//
// With the race condition bug, multiple goroutines would read the same stale
// nc value, produce identical Authorization headers, and the server would
// reject all but one. With the fix, each goroutine gets a unique, monotonically
// increasing nc value under a mutex, so all requests succeed.
func TestDigestAuth_Concurrency(t *testing.T) {
	server := newStrictDigestServer()
	ts := httptest.NewServer(server)
	defer ts.Close()

	client := New()
	client.SetDigestAuth(server.username, server.password)

	const n = 50
	var wg sync.WaitGroup
	errs := make([]error, n)
	statuses := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := client.R().Get(ts.URL)
			if err != nil {
				errs[idx] = err
				return
			}
			statuses[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	// Assert all requests succeeded with 200 OK.
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d error: %v", i, errs[i])
		}
		if statuses[i] != http.StatusOK {
			t.Fatalf("goroutine %d: expected status 200, got %d", i, statuses[i])
		}
	}

	// Verify all 50 nc values were unique (no stale/duplicate counts).
	server.mu.Lock()
	seen := len(server.seenNCs)
	server.mu.Unlock()
	if seen != n {
		t.Fatalf("expected %d unique nc values, got %d — duplicate nonce counts detected", n, seen)
	}
}