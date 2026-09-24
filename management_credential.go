package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Plugin-level in-memory Management credential cache.
// Populated from authenticated Management API requests (page-provided key).
// Never written to disk.
var managementCredentialCache = struct {
	mu  sync.RWMutex
	key string
}{}

func rememberManagementCredential(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	managementCredentialCache.mu.Lock()
	managementCredentialCache.key = key
	managementCredentialCache.mu.Unlock()
	// A different key means the operator fixed the credential: stop refusing it.
	managementGuard.mu.Lock()
	if managementGuard.rejected != "" && managementGuard.rejected != key {
		managementGuard.rejected = ""
		managementGuard.rejectedUntil = time.Time{}
		managementGuard.note = ""
	}
	managementGuard.mu.Unlock()
}

// Management credential rejection / IP-ban guard.
//
// CPA counts every failed management authentication per client IP: five failures
// ban that IP for ~30 minutes, the ban rejects even the correct key, and
// 127.0.0.1 is not exempt. A background worker that keeps retrying a rejected
// credential therefore turns key rotation into a local lockout of the management
// panel itself. So the first explicit rejection is remembered:
//
//   - invalid/missing management key: that exact credential is refused locally
//     and dropped from the memory cache so an env key can take over.
//   - "IP banned ... Try again in Xs": no request until the window ends, because
//     the key itself may well be correct.
const (
	managementRejectionInvalidKey = "invalid_key"
	managementRejectionBanned     = "banned"
)

// managementBanRetrySkew keeps the plugin on the safe side of the ban window.
const managementBanRetrySkew = 2 * time.Second

var managementBanRetryPattern = regexp.MustCompile(`(?i)try again in\s*(?:(\d+)\s*m)?\s*(\d+)\s*s`)

var managementGuard = struct {
	mu            sync.Mutex
	rejected      string
	rejectedUntil time.Time
	banUntil      time.Time
	note          string
}{}

// managementRejectedKeyCooldown bounds the fail-fast window for a rejected key:
// without it, re-authentication with the same (now-valid) key could never be sent
// again. After the cooldown the key is attempted once more; a repeat rejection
// simply re-arms the window.
const managementRejectedKeyCooldown = 5 * time.Minute

// classifyManagementAuthRejection reports whether a management response is an
// explicit credential rejection or an IP-ban notice from CPA. Only CPA's own
// messages count: plugin business errors (e.g. a 403 for a missing UI header)
// must not look like a key problem.
func classifyManagementAuthRejection(status int, raw []byte) (string, time.Duration) {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return "", 0
	}
	body := strings.ToLower(strings.TrimSpace(string(raw)))
	switch {
	case strings.Contains(body, "ip banned") || strings.Contains(body, "too many failed attempts"):
		window := time.Minute
		if match := managementBanRetryPattern.FindStringSubmatch(body); match != nil {
			minutes, _ := strconv.Atoi(match[1])
			seconds, _ := strconv.Atoi(match[2])
			if minutes > 0 || seconds > 0 {
				window = time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
			}
		}
		return managementRejectionBanned, window + managementBanRetrySkew
	case strings.Contains(body, "invalid management key"), strings.Contains(body, "missing management key"):
		return managementRejectionInvalidKey, 0
	}
	return "", 0
}

// managementCredentialBlocked fails fast when this exact credential was already
// rejected, or the host IP is inside a ban window reported by CPA.
func managementCredentialBlocked(password string) error {
	password = strings.TrimSpace(password)
	managementGuard.mu.Lock()
	defer managementGuard.mu.Unlock()
	if managementGuard.rejected != "" && managementGuard.rejected == password {
		if managementGuard.rejectedUntil.IsZero() || time.Now().Before(managementGuard.rejectedUntil) {
			reason := strings.TrimSpace(managementGuard.note)
			if reason == "" {
				reason = "invalid management key"
			}
			return fmt.Errorf("CPA management key rejected earlier (%s); re-login at the management panel with remember-password or provide CPA_MANAGEMENT_KEY / MANAGEMENT_PASSWORD", reason)
		}
		// 冷却结束：允许再用同一个密钥试一次（成功即清零，失败则重新计时）。
		managementGuard.rejected = ""
		managementGuard.rejectedUntil = time.Time{}
		managementGuard.note = ""
	}
	if !managementGuard.banUntil.IsZero() && time.Now().Before(managementGuard.banUntil) {
		remaining := managementGuard.banUntil.Sub(time.Now()).Round(time.Second)
		return fmt.Errorf("CPA management API banned this host IP after too many failed attempts; skipping management calls for %s (restart CPA to clear the ban immediately)", remaining)
	}
	return nil
}

// noteManagementAuthFailure records an explicit rejection so the next attempt
// fails fast instead of burning another failed attempt for the whole IP.
func noteManagementAuthFailure(password string, status int, raw []byte) {
	kind, window := classifyManagementAuthRejection(status, raw)
	if kind == "" {
		return
	}
	password = strings.TrimSpace(password)
	message := strings.TrimSpace(string(raw))
	if len(message) > 200 {
		message = message[:200]
	}
	managementGuard.mu.Lock()
	switch kind {
	case managementRejectionBanned:
		managementGuard.banUntil = time.Now().Add(window)
		managementGuard.note = "CPA reported an IP ban: " + message
		slog.Warn("grok-inspection: CPA banned this host IP for repeated management auth failures; pausing management calls (restarting CPA clears the ban immediately)",
			"retry_after", window.Round(time.Second).String(), "response", message)
	case managementRejectionInvalidKey:
		if managementGuard.rejected != password {
			managementGuard.rejected = password
			managementGuard.note = "CPA rejected the management key: " + message
			slog.Warn("grok-inspection: CPA rejected the management key; pausing calls with this key until a new one is provided (re-login at /management.html with remember-password, or set CPA_MANAGEMENT_KEY / MANAGEMENT_PASSWORD)",
				"response", message)
		}
		managementGuard.rejectedUntil = time.Now().Add(managementRejectedKeyCooldown)
	}
	managementGuard.mu.Unlock()
	if kind == managementRejectionInvalidKey {
		dropRejectedManagementCredential(password)
	}
}

// dropRejectedManagementCredential removes a rejected key from the in-memory
// cache so an env-provided credential can take over.
func dropRejectedManagementCredential(password string) {
	managementCredentialCache.mu.Lock()
	if managementCredentialCache.key == password {
		managementCredentialCache.key = ""
	}
	managementCredentialCache.mu.Unlock()
}

// noteManagementSuccess clears guard state after a successful call.
func noteManagementSuccess(password string) {
	managementGuard.mu.Lock()
	managementGuard.rejected = ""
	managementGuard.rejectedUntil = time.Time{}
	managementGuard.banUntil = time.Time{}
	managementGuard.note = ""
	managementGuard.mu.Unlock()
}

func cachedManagementCredential() string {
	managementCredentialCache.mu.RLock()
	defer managementCredentialCache.mu.RUnlock()
	return strings.TrimSpace(managementCredentialCache.key)
}

// cpaManagementPasswordOrCached returns request-less credential resolution:
// memory cache > MANAGEMENT_PASSWORD / CPA_MANAGEMENT_KEY env.
func cpaManagementPasswordOrCached() string {
	if key := cachedManagementCredential(); key != "" {
		return key
	}
	return cpaManagementPassword()
}

// resolveManagementPassword prefers: request headers > memory cache > env.
// Successful header extraction is remembered for realtime auto-disable paths
// that cannot see the original Management request.
func resolveManagementPassword(headers http.Header) string {
	if headers != nil {
		if token := extractBearerToken(headers); token != "" {
			rememberManagementCredential(token)
			return token
		}
		if token := strings.TrimSpace(headers.Get("X-Management-Key")); token != "" {
			rememberManagementCredential(token)
			return token
		}
		for key, values := range headers {
			if strings.EqualFold(strings.TrimSpace(key), "X-Management-Key") && len(values) > 0 {
				if token := strings.TrimSpace(values[0]); token != "" {
					rememberManagementCredential(token)
					return token
				}
			}
		}
	}
	if key := cachedManagementCredential(); key != "" {
		return key
	}
	return strings.TrimSpace(cpaManagementPassword())
}

// allowInsecureRemoteManagementTLS is a dangerous opt-in for remote self-signed
// CPA management endpoints. Default is false: non-loopback HTTPS must verify.
// Env names are intentionally explicit.
func allowInsecureRemoteManagementTLS() bool {
	return envTruthy(os.Getenv("GROK_INSPECTION_INSECURE_REMOTE_TLS")) ||
		envTruthy(os.Getenv("CPA_MANAGEMENT_TLS_INSECURE"))
}

func managementTLSSkipVerifyForHost(host string) bool {
	if isLoopbackHost(host) {
		return true
	}
	return allowInsecureRemoteManagementTLS()
}
