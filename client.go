// Copyright (c) 2024 Sonja & Cliff
// Licensed under the MIT License.
//
// Simplified resty-style HTTP client with Digest Access Authentication support.

package resty

import (
	"io"
	"net/http"
)

// Client is the resty HTTP client.
type Client struct {
	httpClient *http.Client
}

// New creates a new resty Client with sensible defaults.
func New() *Client {
	return &Client{
		httpClient: &http.Client{},
	}
}

// SetDigestAuth configures the client to use Digest Access Authentication
// with the given credentials. The digest transport maintains shared state
// (nonce, nonce-count, client-nonce) that is synchronized so that concurrent
// requests using the same Client are thread-safe.
func (c *Client) SetDigestAuth(username, password string) *Client {
	c.httpClient.Transport = newDigestTransport(username, password, http.DefaultTransport)
	return c
}

// R creates a new Request.
func (c *Client) R() *Request {
	return &Request{client: c}
}

// Request represents an HTTP request.
type Request struct {
	client *Client
}

// Get sends a GET request and returns the response.
func (r *Request) Get(url string) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{StatusCode: resp.StatusCode, Body: body}, nil
}

// Response represents an HTTP response.
type Response struct {
	StatusCode int
	Body       []byte
}