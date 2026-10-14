package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"grok-inspection/cpasdk/pluginabi"
)

// Dynamic Grok CLI client version for inspection probes, ported from
// CLIProxyAPI internal/runtime/executor/helps/xai_version.go.
//
// cli-chat-proxy.grok.com rejects probe requests whose x-grok-client-version is
// older than the server floor with HTTP 426 (#6249). A hardcoded version rots:
// the plugin previously pinned 0.2.93 and every inspection returned 426. The
// version is therefore resolved from the npm registry in the background and
// cached; the fallback keeps probes working when npm is unreachable.

const (
	// DefaultXAIInspectionClientVersion is the stable Grok CLI version used when
	// npm registry resolution fails. dist-tag latest is 1.0.46; 1.0.50 is alpha.
	DefaultXAIInspectionClientVersion = "1.0.46"
	// XAIInspectionClientVersionServerFloor is the minimum Grok CLI version
	// cli-chat-proxy accepts. Older clients are rejected with HTTP 426.
	XAIInspectionClientVersionServerFloor = "1.0.13"
	// xaiVersionRefreshInterval is the periodic npm registry check interval.
	xaiVersionRefreshInterval = 3 * time.Hour
	// xaiVersionFetchTimeout bounds one npm registry lookup through host.http.do.
	xaiVersionFetchTimeout = 10 * time.Second
	// xaiVersionStartDelay lets plugin registration finish before the first
	// npm lookup so early host.http.do calls are not issued against a half
	// initialized host bridge.
	xaiVersionStartDelay = 2 * time.Second
)

var (
	xaiVersionMu             sync.RWMutex
	cachedXAIInspectVersion  = DefaultXAIInspectionClientVersion
	xaiNPMRegistryURL        = "https://registry.npmjs.org/@xai-official/grok/latest"
	xaiVersionStop           chan struct{}
	xaiVersionDone           chan struct{}
	xaiVersionStartOnce      sync.Once
	xaiVersionStopMutex      sync.Mutex
	xaiVersionRefreshedHooks []chan struct{}
)

// GetXAIInspectionClientVersion returns the active Grok CLI client version for
// probe headers. Until the first successful npm refresh (or when npm stays
// unreachable) this is DefaultXAIInspectionClientVersion.
func GetXAIInspectionClientVersion() string {
	xaiVersionMu.RLock()
	defer xaiVersionMu.RUnlock()
	return cachedXAIInspectVersion
}

// startXAIVersionUpdater launches the background npm version refresher once.
// A failed lookup keeps the previous cached/fallback version; probes never
// block on npm availability.
func startXAIVersionUpdater() {
	xaiVersionStartOnce.Do(func() {
		stop := make(chan struct{})
		done := make(chan struct{})
		xaiVersionStopMutex.Lock()
		xaiVersionStop = stop
		xaiVersionDone = done
		xaiVersionStopMutex.Unlock()
		go runXAIVersionUpdater(stop, done)
	})
}

// stopXAIVersionUpdater terminates the background refresher and waits for it.
// Safe to call multiple times and before start (no-op).
func stopXAIVersionUpdater() {
	xaiVersionStopMutex.Lock()
	stop, done := xaiVersionStop, xaiVersionDone
	xaiVersionStopMutex.Unlock()
	if stop == nil {
		return
	}
	select {
	case <-stop:
		// already closed
	default:
		close(stop)
	}
	if done != nil {
		<-done
	}
}

func runXAIVersionUpdater(stop, done chan struct{}) {
	defer close(done)
	// First pass after a short grace period (covers plugin.register timing).
	select {
	case <-time.After(xaiVersionStartDelay):
	case <-stop:
		return
	}
	refreshXAIInspectionVersion()
	ticker := time.NewTicker(xaiVersionRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			refreshXAIInspectionVersion()
		case <-stop:
			return
		}
	}
}

func refreshXAIInspectionVersion() {
	defer notifyXAIVersionRefreshed()
	version, errFetch := fetchXAINPMLatestVersion()
	if errFetch != nil {
		// Keep fallback/cached version; never disable probing over npm issues.
		return
	}
	xaiVersionMu.Lock()
	changed := cachedXAIInspectVersion != version
	if changed {
		cachedXAIInspectVersion = version
	}
	xaiVersionMu.Unlock()
}

// fetchXAINPMLatestVersion queries the npm registry for the latest
// @xai-official/grok version via the host's proxy-aware HTTP client
// (host.http.do). Returns a strict numeric semver at or above the server floor.
func fetchXAINPMLatestVersion() (string, error) {
	xaiVersionMu.RLock()
	registryURL := xaiNPMRegistryURL
	xaiVersionMu.RUnlock()

	type outcome struct {
		resp apiCallResponse
		err  error
	}
	ch := make(chan outcome, 1)
	go func() {
		result, err := callHost(pluginabi.MethodHostHTTPDo, map[string]any{
			"method": http.MethodGet,
			"url":    registryURL,
			"headers": map[string][]string{
				"Accept":     {"application/json"},
				"User-Agent": {"hk-grok-inspection"},
			},
		})
		if err != nil {
			ch <- outcome{err: err}
			return
		}
		decoded, errDecode := decodeHostHTTPDoResult(result)
		ch <- outcome{resp: decoded, err: errDecode}
	}()
	select {
	case out := <-ch:
		if out.err != nil {
			return "", fmt.Errorf("npm registry request failed: %w", out.err)
		}
		if out.resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("npm registry returned HTTP %d", out.resp.StatusCode)
		}
		return parseXAINPMVersion(out.resp.Body)
	case <-time.After(xaiVersionFetchTimeout):
		return "", errors.New("npm registry request timed out")
	}
}

// parseXAINPMVersion extracts and validates the version field of an npm
// registry "latest" response body.
func parseXAINPMVersion(body string) (string, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", errors.New("npm registry returned empty body")
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return "", fmt.Errorf("decode npm registry response: %w", err)
	}
	version := strings.TrimSpace(payload.Version)
	if version == "" {
		return "", errors.New("version not found in npm response")
	}
	if !acceptableXAIInspectionVersion(version) {
		return "", fmt.Errorf("npm registry returned unacceptable Grok CLI version %s", strconv.Quote(version))
	}
	return version, nil
}

func acceptableXAIInspectionVersion(version string) bool {
	if !isStrictXAIInspectionSemver(version) {
		return false
	}
	return xaiInspectionVersionAtLeast(version, XAIInspectionClientVersionServerFloor)
}

func isStrictXAIInspectionSemver(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

func xaiInspectionVersionAtLeast(got, floor string) bool {
	gotParts := strings.Split(got, ".")
	floorParts := strings.Split(floor, ".")
	for i := 0; i < len(gotParts) || i < len(floorParts); i++ {
		var g, f int
		var errG, errF error
		if i < len(gotParts) {
			g, errG = strconv.Atoi(gotParts[i])
			if errG != nil {
				return false
			}
		}
		if i < len(floorParts) {
			f, errF = strconv.Atoi(floorParts[i])
			if errF != nil {
				return false
			}
		}
		if g != f {
			return g > f
		}
	}
	return true
}

func notifyXAIVersionRefreshed() {
	xaiVersionMu.RLock()
	hooks := append([]chan struct{}(nil), xaiVersionRefreshedHooks...)
	xaiVersionMu.RUnlock()
	for _, ch := range hooks {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// OverrideXAINPMRegistryURLForTest swaps the npm registry URL (tests only).
func OverrideXAINPMRegistryURLForTest(url string) func() {
	xaiVersionMu.Lock()
	old := xaiNPMRegistryURL
	xaiNPMRegistryURL = url
	xaiVersionMu.Unlock()
	return func() {
		xaiVersionMu.Lock()
		xaiNPMRegistryURL = old
		xaiVersionMu.Unlock()
	}
}

// SetXAIInspectionClientVersionForTest sets the cached version directly (tests only).
func SetXAIInspectionClientVersionForTest(version string) func() {
	xaiVersionMu.Lock()
	old := cachedXAIInspectVersion
	cachedXAIInspectVersion = version
	xaiVersionMu.Unlock()
	return func() {
		xaiVersionMu.Lock()
		cachedXAIInspectVersion = old
		xaiVersionMu.Unlock()
	}
}

// SetXAIVersionRefreshedHookForTest receives one signal per refresh attempt (tests only).
func SetXAIVersionRefreshedHookForTest(ch chan struct{}) func() {
	xaiVersionMu.Lock()
	xaiVersionRefreshedHooks = append(xaiVersionRefreshedHooks, ch)
	xaiVersionMu.Unlock()
	return func() {
		xaiVersionMu.Lock()
		filtered := xaiVersionRefreshedHooks[:0]
		for _, hook := range xaiVersionRefreshedHooks {
			if hook != ch {
				filtered = append(filtered, hook)
			}
		}
		xaiVersionRefreshedHooks = filtered
		xaiVersionMu.Unlock()
	}
}
