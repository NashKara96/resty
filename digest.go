// Copyright (c) 2024 Sonja & Cliff
// Licensed under the MIT License.
//
// Digest Access Authentication with thread-safe state management.
//
// BUG FIX: The original implementation mutated the nonce count (nc) and
// client nonce (cnonce) concurrently without synchronization, causing
// data races and stale nonce counts. This file introduces a sync.Mutex
// to protect the shared digest state and ensures that nc monotonically
// increases for any given active server nonce.

package resty

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// digestCredentials stores the username and password for digest auth.
type digestCredentials struct {
	username, password string
}

// digestTransport implements http.RoundTripper with Digest Access Authentication.
//
// The mu mutex protects the shared digest state fields (nonce, nc, cnonce,
// realm, algorithm, qop, opaque) so that concurrent goroutines using the same
// Client cannot race on the nonce count. Each call to buildAuthRequest
// atomically increments nc and generates a fresh cnonce under the lock,
// then builds the Authorization header from a snapshot outside the lock.
type digestTransport struct {
	digestCredentials
	transport http.RoundTripper

	mu        sync.Mutex // protects the fields below
	nonce     string     // server-issued nonce for the current session
	nc        int        // nonce count — monotonically increases per nonce
	cnonce    string     // client nonce — regenerated for each request
	realm     string
	algorithm string
	qop       string
	opaque    string
}

func newDigestTransport(username, password string, transport http.RoundTripper) *digestTransport {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &digestTransport{
		digestCredentials: digestCredentials{username: username, password: password},
		transport:         transport,
	}
}

// RoundTrip implements http.RoundTripper. It first sends the request without
// authentication. If the server responds with a 401 Digest challenge, it
// builds an authenticated request and retries. If the authenticated request
// also receives a 401 with stale=true (nonce expired), it retries once more
// with the new nonce and a reset nc counter.
func (dt *digestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// First request — may receive 401 with the digest challenge.
	resp, err := dt.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	chal := resp.Header.Get("WWW-Authenticate")
	if chal == "" {
		return resp, nil
	}

	c, err := parseChallenge(chal)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	_ = resp.Body.Close()

	// Build and send the authenticated request.
	authReq, err := dt.buildAuthRequest(req, c)
	if err != nil {
		return nil, err
	}

	authResp, err := dt.transport.RoundTrip(authReq)
	if err != nil {
		return nil, err
	}

	// If the server returns 401 with stale=true, the nonce has expired.
	// Retry with the new nonce and a reset nc counter.
	if authResp.StatusCode == http.StatusUnauthorized {
		staleChal := authResp.Header.Get("WWW-Authenticate")
		if staleChal != "" {
			sc, parseErr := parseChallenge(staleChal)
			if parseErr == nil && sc.stale == "true" {
				_ = authResp.Body.Close()
				authReq2, err := dt.buildAuthRequest(req, sc)
				if err != nil {
					return nil, err
				}
				return dt.transport.RoundTrip(authReq2)
			}
		}
	}

	return authResp, nil
}

// buildAuthRequest atomically updates the shared digest state under mu,
// snapshots the values, then builds the Authorization header outside the
// lock. This ensures that:
//   - nc monotonically increases for the active nonce (no stale reads).
//   - A new server nonce safely resets nc to 1.
//   - The Authorization header is computed from a consistent snapshot.
func (dt *digestTransport) buildAuthRequest(req *http.Request, c *challenge) (*http.Request, error) {
	dt.mu.Lock()

	// If the server returned a new nonce, reset the nonce count and update
	// all challenge-derived fields. This handles both the initial challenge
	// and the stale=true nonce-refresh case.
	if c.nonce != dt.nonce {
		dt.nonce = c.nonce
		dt.nc = 0 // will be incremented to 1 below
		dt.realm = c.realm
		dt.algorithm = c.algorithm
		dt.qop = c.qop
		dt.opaque = c.opaque
	}

	// Increment nc — this is the core of the fix. Under the mutex, each
	// goroutine is guaranteed a unique, monotonically increasing value.
	dt.nc++
	nc := dt.nc

	// Generate a fresh client nonce for this request.
	cnonce, err := generateCnonce()
	if err != nil {
		dt.mu.Unlock()
		return nil, err
	}
	dt.cnonce = cnonce

	// Snapshot all values needed to build the Authorization header.
	// This allows the MD5 computation to happen outside the lock.
	snap := digestSnapshot{
		username:  dt.username,
		password:  dt.password,
		realm:     dt.realm,
		nonce:     dt.nonce,
		nc:        nc,
		cnonce:    cnonce,
		algorithm: dt.algorithm,
		qop:       dt.qop,
		opaque:    dt.opaque,
	}

	dt.mu.Unlock()

	// Build the Authorization header from the snapshot (no lock needed).
	auth, err := buildAuthHeader(snap, req.Method, req.URL.RequestURI())
	if err != nil {
		return nil, err
	}

	authReq := req.Clone(req.Context())
	authReq.Header.Set("Authorization", auth)
	return authReq, nil
}

// digestSnapshot is an immutable snapshot of the digest state used to build
// the Authorization header outside the lock.
type digestSnapshot struct {
	username  string
	password  string
	realm     string
	nonce     string
	nc        int
	cnonce    string
	algorithm string
	qop       string
	opaque    string
}

// challenge represents a parsed WWW-Authenticate Digest challenge.
type challenge struct {
	realm     string
	nonce     string
	opaque    string
	stale     string
	algorithm string
	qop       string
}

var challengeRe = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^,]+))`)

// parseChallenge parses a WWW-Authenticate Digest challenge string.
func parseChallenge(input string) (*challenge, error) {
	if !strings.HasPrefix(input, "Digest ") {
		return nil, fmt.Errorf("digest: challenge is bad")
	}
	input = strings.TrimSpace(input[7:])

	c := &challenge{}
	for _, m := range challengeRe.FindAllStringSubmatch(input, -1) {
		key, val := m[1], m[2]
		if val == "" {
			val = strings.TrimSpace(m[3])
		}
		switch key {
		case "realm":
			c.realm = val
		case "nonce":
			c.nonce = val
		case "opaque":
			c.opaque = val
		case "stale":
			c.stale = val
		case "algorithm":
			c.algorithm = val
		case "qop":
			c.qop = val
		}
	}

	if c.nonce == "" {
		return nil, fmt.Errorf("digest: challenge missing nonce")
	}
	return c, nil
}

// generateCnonce generates a random 32-character hex client nonce.
func generateCnonce() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// md5hex computes the hex-encoded MD5 hash of s.
func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// buildAuthHeader builds a Digest Authorization header from a snapshot of
// the digest state. It computes the MD5 response hash per RFC 7616 with
// qop=auth:
//
//	HA1 = MD5(username:realm:password)
//	HA2 = MD5(method:uri)
//	response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
func buildAuthHeader(s digestSnapshot, method, uri string) (string, error) {
	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", s.username, s.realm, s.password))
	ha2 := md5hex(fmt.Sprintf("%s:%s", method, uri))
	response := md5hex(fmt.Sprintf("%s:%s:%08x:%s:%s:%s",
		ha1, s.nonce, s.nc, s.cnonce, s.qop, ha2))

	parts := []string{
		fmt.Sprintf(`username="%s"`, s.username),
		fmt.Sprintf(`realm="%s"`, s.realm),
		fmt.Sprintf(`nonce="%s"`, s.nonce),
		fmt.Sprintf(`uri="%s"`, uri),
		fmt.Sprintf(`response="%s"`, response),
		fmt.Sprintf(`algorithm=%s`, s.algorithm),
		fmt.Sprintf(`qop=%s`, s.qop),
		fmt.Sprintf(`nc=%08x`, s.nc),
		fmt.Sprintf(`cnonce="%s"`, s.cnonce),
	}
	if s.opaque != "" {
		parts = append(parts, fmt.Sprintf(`opaque="%s"`, s.opaque))
	}

	return "Digest " + strings.Join(parts, ", "), nil
}