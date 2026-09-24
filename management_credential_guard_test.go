package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// CPA counts every failed management authentication per client IP: five failures
// ban that IP for ~30 minutes, the ban rejects even the correct key, and the ban
// also blocks the management panel served from that same IP. A background worker
// that keeps retrying a rejected key therefore escalates a stale credential into
// a local lockout, so the first explicit rejection must be remembered.

func resetManagementGuardForTest(t *testing.T) {
	t.Helper()
	managementGuard.mu.Lock()
	managementGuard.rejected = ""
	managementGuard.rejectedUntil = time.Time{}
	managementGuard.banUntil = time.Time{}
	managementGuard.note = ""
	managementGuard.mu.Unlock()
	t.Cleanup(func() {
		managementGuard.mu.Lock()
		managementGuard.rejected = ""
		managementGuard.rejectedUntil = time.Time{}
		managementGuard.banUntil = time.Time{}
		managementGuard.note = ""
		managementGuard.mu.Unlock()
	})
}

func guardTestManagementServer(t *testing.T, status int, body string) (*atomic.Int64, *atomic.Bool) {
	t.Helper()
	var requests atomic.Int64
	var succeeding atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if succeeding.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	oldBase, oldDo := getCPAManagementBaseURL(), getCPAManagementDo()
	setCPAManagementBaseURL(server.URL)
	setCPAManagementDo(server.Client().Do)
	t.Cleanup(func() {
		setCPAManagementBaseURL(oldBase)
		setCPAManagementDo(oldDo)
	})
	return &requests, &succeeding
}

func guardTestCall(password string) error {
	_, _, err := callCPAManagementWithAuth(
		http.MethodPatch,
		"/v0/management/auth-files/status",
		[]byte(`{"name":"guard-auth","disabled":true}`),
		password,
		nil,
	)
	return err
}

// RED: a rejected key keeps being retried for every background attempt.
func TestManagementGuardStopsRetryingRejectedKey(t *testing.T) {
	resetManagementGuardForTest(t)
	requests, _ := guardTestManagementServer(t, http.StatusUnauthorized, `{"error":"invalid management key"}`)

	if errFirst := guardTestCall("stale-page-key"); errFirst == nil {
		t.Fatal("expected the management call to fail on a rejected key")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("first call requests = %d, want 1", got)
	}

	errSecond := guardTestCall("stale-page-key")
	if errSecond == nil {
		t.Fatal("expected the rejected key to fail fast without another request")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("rejected key must not be retried: requests = %d, want 1", got)
	}
	if !strings.Contains(errSecond.Error(), "rejected") {
		t.Fatalf("fail-fast error should explain the rejection: %v", errSecond)
	}

	// A different credential must still be attempted (re-login / env rotation).
	if errFresh := guardTestCall("fresh-page-key"); errFresh == nil {
		t.Fatal("expected the fresh key call to reach the server and fail there")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("fresh credential must be attempted: requests = %d, want 2", got)
	}
}

// RED: an IP ban window is ignored, so every retry burns more attempts.
func TestManagementGuardHonorsIPBanWindow(t *testing.T) {
	resetManagementGuardForTest(t)
	requests, _ := guardTestManagementServer(t, http.StatusForbidden,
		`{"error":"IP banned due to too many failed attempts. Try again in 45s"}`)

	errFirst := guardTestCall("good-key")
	if errFirst == nil {
		t.Fatal("expected the management call to fail while the IP is banned")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("first call requests = %d, want 1", got)
	}

	errSecond := guardTestCall("good-key")
	if errSecond == nil {
		t.Fatal("expected a fail-fast error while the ban window is active")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("banned window must not send requests: requests = %d, want 1", got)
	}
	if !strings.Contains(errSecond.Error(), "banned") {
		t.Fatalf("fail-fast error should mention the ban: %v", errSecond)
	}

	// The key itself may be perfectly valid: once the window is over, try again.
	managementGuard.mu.Lock()
	managementGuard.banUntil = time.Now().Add(-time.Second)
	managementGuard.mu.Unlock()

	if errAfter := guardTestCall("good-key"); errAfter == nil {
		t.Fatal("expected the call after the ban window to reach the server")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("call after ban window requests = %d, want 2", got)
	}
}

// RED: guard state is never cleared, so a rotated key would stay blocked.
func TestManagementGuardClearsOnSuccess(t *testing.T) {
	resetManagementGuardForTest(t)
	requests, succeeding := guardTestManagementServer(t, http.StatusUnauthorized, `{"error":"invalid management key"}`)

	if err := guardTestCall("rotating-key"); err == nil {
		t.Fatal("expected the first call to be rejected")
	}
	// A later attempt with the same value is skipped locally.
	if err := guardTestCall("rotating-key"); err == nil {
		t.Fatal("expected the rejected key to fail fast")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests before recovery = %d, want 1", got)
	}

	// A different credential succeeds: the guard must clear so the value is usable again.
	succeeding.Store(true)
	rememberManagementCredential("rotated-key")
	if err := guardTestCall("rotated-key"); err != nil {
		t.Fatalf("rotated credential should succeed: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests after rotation = %d, want 2", got)
	}

	succeeding.Store(false)
	if err := guardTestCall("rotated-key"); err == nil {
		t.Fatal("expected the rejected mock server to fail again")
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("cleared guard must attempt fresh requests: requests = %d, want 3", got)
	}
}

// RED: the background auto-disable path retries a stale cached page key forever.
func TestDisableAuthInCPADoesNotRetryStaleCachedCredential(t *testing.T) {
	resetManagementGuardForTest(t)
	issue21ClearEnvPassword(t)
	clearManagementCredentialCacheForTest()
	t.Cleanup(clearManagementCredentialCacheForTest)
	requests, _ := guardTestManagementServer(t, http.StatusUnauthorized, `{"error":"invalid management key"}`)

	rememberManagementCredential("stale-page-key")

	if err := disableAuthInCPA("guard-stale-auth"); err == nil {
		t.Fatal("expected disableAuthInCPA to fail with a rejected credential")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("first auto-disable attempt requests = %d, want 1", got)
	}
	if err := disableAuthInCPA("guard-stale-auth"); err == nil {
		t.Fatal("expected the second auto-disable attempt to fail fast")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("auto-disable must not keep burning attempts: requests = %d, want 1", got)
	}
}

// A rejected credential must be dropped so an env-provided key can take over.
func TestManagementGuardDropsRejectedCachedCredential(t *testing.T) {
	resetManagementGuardForTest(t)
	issue21ClearEnvPassword(t)
	clearManagementCredentialCacheForTest()
	t.Cleanup(clearManagementCredentialCacheForTest)
	guardTestManagementServer(t, http.StatusUnauthorized, `{"error":"invalid management key"}`)

	rememberManagementCredential("stale-page-key")
	if got := cachedManagementCredential(); got != "stale-page-key" {
		t.Fatalf("cache precondition = %q", got)
	}
	if err := disableAuthInCPA("guard-drop-auth"); err == nil {
		t.Fatal("expected the rejected credential to fail")
	}
	if got := cachedManagementCredential(); got != "" {
		t.Fatalf("rejected credential must be dropped from the cache, got %q", got)
	}
}

// The fail-fast window must be bounded: re-authenticating with the same key again
// has to become possible, otherwise a recovered credential stays blocked forever.
func TestManagementGuardRejectedKeyRecoversAfterCooldown(t *testing.T) {
	resetManagementGuardForTest(t)
	requests, _ := guardTestManagementServer(t, http.StatusUnauthorized, `{"error":"invalid management key"}`)

	if err := guardTestCall("recovering-key"); err == nil {
		t.Fatal("expected the first call to be rejected")
	}
	for i := 0; i < 3; i++ {
		if err := guardTestCall("recovering-key"); err == nil {
			t.Fatal("expected the rejected key to fail fast")
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("repeated retries must not burn attempts: requests = %d, want 1", got)
	}

	// Cooldown elapsed: the same key is attempted once more.
	managementGuard.mu.Lock()
	managementGuard.rejectedUntil = time.Now().Add(-time.Second)
	managementGuard.mu.Unlock()
	if err := guardTestCall("recovering-key"); err == nil {
		t.Fatal("expected the post-cooldown attempt to reach the server")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("post-cooldown attempt requests = %d, want 2", got)
	}
	// A repeat rejection re-arms the window.
	if err := guardTestCall("recovering-key"); err == nil {
		t.Fatal("expected the re-rejected key to fail fast again")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("re-armed window requests = %d, want 2", got)
	}
}
