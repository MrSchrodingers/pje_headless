package loginsvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildTestJWT builds a signed-less JWT with the given exp for use in tests.
func buildTestJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{"sub": "test", "exp": exp})
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadEnc + "." + sig
}

// TestManager_CacheHit verifies that a second GetBearer call within the token's
// validity window does NOT call loginFn again (serves from cache).
func TestManager_CacheHit(t *testing.T) {
	var callCount int32
	expUnix := time.Now().Add(10 * time.Minute).Unix()
	bearer := buildTestJWT(expUnix)

	loginFn := func(_ context.Context) (string, error) {
		atomic.AddInt32(&callCount, 1)
		return bearer, nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)
	ctx := context.Background()

	b1, _, fromCache1, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("first GetBearer: %v", err)
	}
	if fromCache1 {
		t.Error("first call should not be from cache")
	}

	b2, _, fromCache2, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("second GetBearer: %v", err)
	}
	if !fromCache2 {
		t.Error("second call should be from cache")
	}
	if b1 != b2 {
		t.Errorf("bearer changed: got %q, want %q", b2, b1)
	}
	if n := atomic.LoadInt32(&callCount); n != 1 {
		t.Errorf("loginFn called %d times, want 1", n)
	}
}

// TestManager_ForceBypassesCache verifies that force=true triggers a new login
// even when a valid cached token exists.
func TestManager_ForceBypassesCache(t *testing.T) {
	var callCount int32
	expUnix := time.Now().Add(10 * time.Minute).Unix()

	loginFn := func(_ context.Context) (string, error) {
		n := atomic.AddInt32(&callCount, 1)
		return buildTestJWT(expUnix) + fmt.Sprintf("_call%d", n), nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)
	ctx := context.Background()

	_, _, _, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("first GetBearer: %v", err)
	}

	_, _, fromCache, err := mgr.GetBearer(ctx, true)
	if err != nil {
		t.Fatalf("forced GetBearer: %v", err)
	}
	if fromCache {
		t.Error("force=true should not serve from cache")
	}
	if n := atomic.LoadInt32(&callCount); n != 2 {
		t.Errorf("loginFn called %d times, want 2", n)
	}
}

// TestManager_Expiry verifies that GetBearer refreshes (calls loginFn again)
// when the cached token is within the refresh margin of its expiry.
func TestManager_Expiry(t *testing.T) {
	var callCount int32

	// Build a JWT that expires in 30s - within the default 60s refresh margin.
	expUnix := time.Now().Add(30 * time.Second).Unix()
	bearer := buildTestJWT(expUnix)

	loginFn := func(_ context.Context) (string, error) {
		atomic.AddInt32(&callCount, 1)
		return bearer, nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)
	ctx := context.Background()

	// Prime the cache with the soon-to-expire token by force.
	mgr.primeCache(bearer, time.Unix(expUnix, 0))

	// GetBearer without force: should detect near-expiry and call loginFn.
	_, _, fromCache, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("GetBearer after near-expiry: %v", err)
	}
	if fromCache {
		t.Error("near-expired token should trigger refresh, not serve from cache")
	}
	if n := atomic.LoadInt32(&callCount); n != 1 {
		t.Errorf("loginFn called %d times, want 1", n)
	}
}

// TestManager_CoalescingConcurrent is the falseable coalescing test.
//
// A naive (non-coalescing) implementation would invoke loginFn K times (once
// per goroutine).  The coalescing manager must invoke it exactly once and
// return the same bearer to all K callers.
//
// The fake loginFn blocks on a gate channel until the test releases it, so all
// K goroutines can arrive at the slow path before any one of them completes.
func TestManager_CoalescingConcurrent(t *testing.T) {
	const K = 20

	var callCount int32
	gate := make(chan struct{}) // all goroutines block here until we release

	expUnix := time.Now().Add(10 * time.Minute).Unix()
	expectedBearer := buildTestJWT(expUnix)

	loginFn := func(_ context.Context) (string, error) {
		atomic.AddInt32(&callCount, 1)
		<-gate // block until test unblocks
		return expectedBearer, nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)
	ctx := context.Background()

	type result struct {
		bearer    string
		fromCache bool
		err       error
	}
	results := make([]result, K)
	var wg sync.WaitGroup
	wg.Add(K)

	for i := 0; i < K; i++ {
		i := i
		go func() {
			defer wg.Done()
			b, _, fc, err := mgr.GetBearer(ctx, false)
			results[i] = result{bearer: b, fromCache: fc, err: err}
		}()
	}

	// Give goroutines time to pile up at the slow path before releasing.
	time.Sleep(50 * time.Millisecond)
	close(gate) // unblock the single loginFn call
	wg.Wait()

	// loginFn must have been called exactly once.
	if n := atomic.LoadInt32(&callCount); n != 1 {
		t.Errorf("loginFn called %d times, want 1 (coalescing failed)", n)
	}

	// Every caller must have received the correct bearer and no error.
	for i, r := range results {
		if r.err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, r.err)
		}
		if r.bearer != expectedBearer {
			t.Errorf("goroutine %d: got bearer %q, want %q", i, r.bearer, expectedBearer)
		}
	}
}

// TestManager_ErrorPropagatesAndLeavesCache verifies that when loginFn returns
// an error, the error propagates to the caller and the prior cached value is
// left intact (the cache is not poisoned).
func TestManager_ErrorPropagatesAndLeavesCache(t *testing.T) {
	var callCount int32
	expUnix := time.Now().Add(10 * time.Minute).Unix()
	cachedBearer := buildTestJWT(expUnix)

	errLogin := errors.New("login failed: network timeout")
	shouldFail := false

	loginFn := func(_ context.Context) (string, error) {
		atomic.AddInt32(&callCount, 1)
		if shouldFail {
			return "", errLogin
		}
		return cachedBearer, nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)
	ctx := context.Background()

	// Prime the cache with a good token.
	b1, _, _, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("initial GetBearer: %v", err)
	}

	// Now trigger a forced refresh that fails.
	shouldFail = true
	_, _, _, err = mgr.GetBearer(ctx, true)
	if err == nil {
		t.Fatal("expected error from failed loginFn, got nil")
	}
	if !errors.Is(err, errLogin) {
		t.Errorf("error mismatch: got %v, want %v", err, errLogin)
	}

	// The cache must still return the original bearer (not poisoned).
	// We need to flip shouldFail back; but actually the cache hit will
	// never call loginFn, so this just verifies the cache is intact.
	shouldFail = false
	b2, _, fromCache, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("GetBearer after error: %v", err)
	}
	if !fromCache {
		t.Error("expected cached token after failed refresh, got fromCache=false")
	}
	if b2 != b1 {
		t.Errorf("cache poisoned: got %q, want original %q", b2, b1)
	}
}

// TestManager_UnparsableTokenGetsTTL verifies that when loginFn returns a token
// that parseBearerExp cannot parse (no exp), the manager still caches it with
// the conservative defaultTTL rather than rejecting it.
func TestManager_UnparsableTokenGetsTTL(t *testing.T) {
	var callCount int32
	opaqueToken := "opaque-token-no-exp"

	loginFn := func(_ context.Context) (string, error) {
		atomic.AddInt32(&callCount, 1)
		return opaqueToken, nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)
	ctx := context.Background()

	b1, _, _, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("first GetBearer: %v", err)
	}
	if b1 != opaqueToken {
		t.Errorf("got bearer %q, want %q", b1, opaqueToken)
	}

	// Second call should hit cache (token has defaultTTL, far from expiry).
	b2, _, fromCache, err := mgr.GetBearer(ctx, false)
	if err != nil {
		t.Fatalf("second GetBearer: %v", err)
	}
	if !fromCache {
		t.Error("second call for opaque token should serve from cache")
	}
	if b2 != b1 {
		t.Errorf("bearer changed: got %q, want %q", b2, b1)
	}
	if n := atomic.LoadInt32(&callCount); n != 1 {
		t.Errorf("loginFn called %d times, want 1", n)
	}
}

// TestManager_Snapshot verifies that Snapshot reflects the cache state without
// triggering a login.
func TestManager_Snapshot(t *testing.T) {
	var callCount int32
	expUnix := time.Now().Add(10 * time.Minute).Unix()
	bearer := buildTestJWT(expUnix)

	loginFn := func(_ context.Context) (string, error) {
		atomic.AddInt32(&callCount, 1)
		return bearer, nil
	}

	mgr := NewManager(loginFn, defaultRefreshMargin, nil)

	// Before any login: Snapshot should report no bearer.
	hasBefore, _ := mgr.Snapshot()
	if hasBefore {
		t.Error("Snapshot before login should report hasBefore=false")
	}
	if n := atomic.LoadInt32(&callCount); n != 0 {
		t.Errorf("Snapshot triggered loginFn; callCount=%d, want 0", n)
	}

	// After a successful login: Snapshot should report the bearer.
	_, _, _, err := mgr.GetBearer(context.Background(), false)
	if err != nil {
		t.Fatalf("GetBearer: %v", err)
	}

	hasAfter, exp := mgr.Snapshot()
	if !hasAfter {
		t.Error("Snapshot after login should report hasBefore=true")
	}
	if exp.Unix() != expUnix {
		t.Errorf("Snapshot exp: got %d, want %d", exp.Unix(), expUnix)
	}
}

// TestManager_Snapshot_StaleReportsFalse pins the contract that Health relies on:
// a cached bearer whose expiry is already inside the refresh margin is NOT a
// usable token, so Snapshot must report hasBearer=false (the proto documents
// Health as reporting a "non-expired" bearer), while still returning the cached
// expiry so a caller can see when it lapses. This guards the isFresh() check in
// Snapshot: dropping it would make this test report a stale token as present.
func TestManager_Snapshot_StaleReportsFalse(t *testing.T) {
	mgr := NewManager(
		func(_ context.Context) (string, error) {
			return "", errors.New("loginFn must not be called by Snapshot")
		},
		defaultRefreshMargin, // 60s margin
		nil,
	)

	// Expiry 30s out: inside the 60s margin, so isFresh() is false -> stale.
	staleExp := time.Now().Add(30 * time.Second)
	mgr.primeCache(buildTestJWT(staleExp.Unix()), staleExp)

	has, exp := mgr.Snapshot()
	if has {
		t.Error("Snapshot of a within-margin (stale) token must report hasBearer=false")
	}
	if exp.IsZero() {
		t.Error("Snapshot must still return the cached expiry even when the token is stale")
	}
}
