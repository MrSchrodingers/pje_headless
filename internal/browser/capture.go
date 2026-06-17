package browser

import (
	"strings"
	"sync"
)

// apiURLSubstring is the marker that identifies the target API call whose
// Authorization header carries the bearer token. It mirrors the
// driver.wait_for_request(r".*/api/v2/processos/.*") pattern in
// vigia/services/pje_worker.py.
const apiURLSubstring = "/api/v2/processos/"

// bearerCapture correlates CDP Network events to extract the bearer token from
// the first request whose URL matches the target API, replacing selenium-wire.
//
// The URL is observed on the requestWillBeSent event, while the final raw
// headers (including the Authorization injected by the Angular app) arrive on
// requestWillBeSentExtraInfo. The two events share a RequestID. Either may
// arrive first, so both observed URLs and observed headers are buffered per
// RequestID and joined when both are present.
//
// bearerCapture is safe for concurrent use because CDP event listeners run on
// the chromedp event goroutine while bearer() may be polled elsewhere.
type bearerCapture struct {
	mu      sync.Mutex
	urls    map[string]string // requestID -> URL
	headers map[string]string // requestID -> Authorization value (raw, as sent)
	token   string            // first matched, non-empty bearer
}

func newBearerCapture() *bearerCapture {
	return &bearerCapture{
		urls:    make(map[string]string),
		headers: make(map[string]string),
	}
}

// onRequest records the URL seen on a requestWillBeSent event.
func (c *bearerCapture) onRequest(requestID, url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.urls[requestID] = url
	c.tryMatchLocked(requestID)
}

// onExtraInfo records the raw headers seen on a requestWillBeSentExtraInfo
// event. headers keys are matched case-insensitively for "Authorization".
func (c *bearerCapture) onExtraInfo(requestID string, headers map[string]any) {
	auth := authHeaderValue(headers)
	c.mu.Lock()
	defer c.mu.Unlock()
	if auth != "" {
		c.headers[requestID] = auth
	}
	c.tryMatchLocked(requestID)
}

// tryMatchLocked promotes a buffered (url, auth) pair to the captured token
// when both are known, the URL matches the target API, and the auth is
// non-blank. The first such match wins. Caller must hold c.mu.
func (c *bearerCapture) tryMatchLocked(requestID string) {
	if c.token != "" {
		return
	}
	url, hasURL := c.urls[requestID]
	auth, hasAuth := c.headers[requestID]
	if !hasURL || !hasAuth {
		return
	}
	if !strings.Contains(url, apiURLSubstring) {
		return
	}
	if strings.TrimSpace(auth) == "" {
		return
	}
	c.token = strings.TrimSpace(auth)
}

// bearer returns the captured bearer token, if any. The second return value
// reports whether a token was captured.
func (c *bearerCapture) bearer() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return "", false
	}
	return c.token, true
}

// authHeaderValue extracts the Authorization header value from a CDP headers
// map, matching the key case-insensitively and ignoring non-string values.
func authHeaderValue(headers map[string]any) string {
	for k, v := range headers {
		if !strings.EqualFold(k, "Authorization") {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.TrimSpace(s) == "" {
			continue
		}
		return s
	}
	return ""
}
