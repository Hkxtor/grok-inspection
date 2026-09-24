package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The resource page reuses the Management Center key from the same-origin
// localStorage. CPA counts every failed management authentication per client IP
// (a missing key counts too): five failures ban that IP for ~30 minutes, the ban
// rejects even the correct key, and 127.0.0.1 is not exempt. On a local install
// the browser shares that IP, so a stale key plus an unattended poll loop locks
// the operator out of the management panel itself. Upstream keeps the ban on
// purpose (issue #4013), so these tests pin the plugin-side contract that keeps
// the page from burning failed attempts.

func TestResourcePageManagementAuthContract(t *testing.T) {
	page := string(renderUIPage(pluginName))

	// Shared auth module is wired into the page.
	for _, marker := range []string{
		`GI_AUTH_STORAGE_KEYS = ['cli-proxy-auth']`,
		`function giResolveManagementKey(storage)`,
		`function giClassifyManagementFailure(status, body)`,
		`function giPollDecision(kind, failureCount)`,
		`function giBlockPolling(failure, announce)`,
		`function bootManagementLoad()`,
		`function giResetBootHydrate()`,
	} {
		if !strings.Contains(page, marker) {
			t.Fatalf("resource page missing marker %q", marker)
		}
	}

	// Key resolution is delegated; guessed storage names are gone.
	if !strings.Contains(uiScriptCore, "giResolveManagementKey(store)") {
		t.Fatal("panel key extraction must delegate to giResolveManagementKey")
	}
	// The shared module must be defined before the core chunk that calls it, and the
	// panel obfuscation consts must be initialized before the first key resolution
	// (otherwise the page throws a TDZ error while it boots).
	moduleAt := strings.Index(page, "function giResolveManagementKey(storage)")
	extractAt := strings.Index(page, "function extractKeyFromPanelStorage()")
	if moduleAt < 0 || extractAt < 0 || moduleAt > extractAt {
		t.Fatalf("auth module must be defined before extractKeyFromPanelStorage: %d %d", moduleAt, extractAt)
	}
	panelConstAt := strings.Index(page, "const PANEL_SECRET_SALT")
	firstResolveAt := strings.Index(page, "let bootKey = loadStoredManagementKey();")
	if panelConstAt < 0 || firstResolveAt < 0 || panelConstAt > firstResolveAt {
		t.Fatalf("panel obfuscation consts must be initialized before the first key resolution: %d %d", panelConstAt, firstResolveAt)
	}
	for _, forbidden := range []string{`'cli-proxy-management-key'`, `'CPA_MANAGEMENT_KEY'`, `'management_password'`, `authToken`} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("resource page must not read the guessed storage key %q", forbidden)
		}
	}

	// No management request without a key, and auth failures stop the poll loop.
	if !strings.Contains(uiScriptSchedule, `throw giManagementError('invalid_key', 0, t('need_key'))`) {
		t.Fatal("api() must refuse to fetch without a management key")
	}
	if !strings.Contains(uiScriptSchedule, "giBlockPolling(failure, false)") {
		t.Fatal("api() must block polling when the management API rejects the key")
	}
	if !strings.Contains(uiScriptPoll, "if (giAuthBlocked) { stopPolling(); return; }") {
		t.Fatal("polling must re-check the blocked state before scheduling the next request")
	}
	if strings.Contains(uiScriptPoll, "setInterval") {
		t.Fatal("polling must not use an unbounded setInterval loop")
	}
	if !strings.Contains(uiScriptPoll, "clearTimeout(pollTimer)") {
		t.Fatal("stopPolling must clear the self-scheduled poll timer")
	}
	if !strings.Contains(uiScriptPoll, "if (pollInFlight) { startPolling(); return; }") {
		t.Fatal("poll ticks must not overlap")
	}
	// 熔断状态必须先清除再决定是否继续轮询，否则解封后手动刷新成功也无法重新起表。
	noteAt := strings.Index(uiScriptPoll, "giNoteSuccess();")
	syncAt := strings.Index(uiScriptPoll, "syncPolling(data);")
	if noteAt < 0 || syncAt < 0 || noteAt > syncAt {
		t.Fatalf("refresh() must clear the block before syncPolling decides: note=%d sync=%d", noteAt, syncAt)
	}

	// Boot goes through one serial validation request instead of a request burst.
	if !strings.Contains(uiScriptBan, "bootManagementLoad();") {
		t.Fatal("boot must load through bootManagementLoad()")
	}
	if strings.Contains(uiScriptBan, "loadBans();\n    loadSchedule();") {
		t.Fatal("boot must not fire loadBans() and loadSchedule() concurrently")
	}
	if strings.Contains(uiScriptCore, "if (hasManagementKey()) { refresh(); loadSchedule(); }") {
		t.Fatal("late key discovery must go through bootManagementLoad()")
	}
	if !strings.Contains(uiScriptAuth, "function giScheduleBootRetry()") {
		t.Fatal("auth module must expose the boot retry policy")
	}
	if !strings.Contains(uiScriptAuth, "clearTimeout(giBootRetryTimer)") {
		t.Fatal("boot retry must be cancelable")
	}
	boot := uiScriptAuth[strings.Index(uiScriptAuth, "async function bootManagementLoad()"):]
	validateAt := strings.Index(boot, "await loadSchedule()")
	refreshAt := strings.Index(boot, "await refresh()")
	bansAt := strings.Index(boot, "await loadBans()")
	if validateAt < 0 || refreshAt < 0 || bansAt < 0 || !(validateAt < refreshAt && refreshAt < bansAt) {
		t.Fatalf("boot must validate, then refresh, then load bans in order: %d %d %d", validateAt, refreshAt, bansAt)
	}
	if !strings.Contains(uiScriptSchedule, "const raw = await api('/schedule')") {
		t.Fatal("loadSchedule must remain the single auth validation request")
	}
	if strings.Contains(uiScriptSchedule, "Promise.all") {
		t.Fatal("loadSchedule must not fire parallel management requests")
	}
}

// The resource page ships as a single inline script assembled from several Go
// constants; a syntax error in any chunk would silently break the panel.
func TestRenderedPageScriptParses(t *testing.T) {
	nodePath, errLookup := exec.LookPath("node")
	if errLookup != nil {
		t.Skipf("node not available to parse the page script: %v", errLookup)
	}
	page := string(renderUIPage(pluginName))
	openIndex := strings.LastIndex(page, "<script>")
	closeIndex := strings.LastIndex(page, "</script>")
	if openIndex < 0 || closeIndex <= openIndex {
		t.Fatalf("inline script block not found: open=%d close=%d", openIndex, closeIndex)
	}
	body := page[openIndex+len("<script>") : closeIndex]
	target := filepath.Join(t.TempDir(), "page.js")
	if errWrite := os.WriteFile(target, []byte(body), 0o600); errWrite != nil {
		t.Fatalf("write page script: %v", errWrite)
	}
	out, errRun := exec.Command(nodePath, "--check", target).CombinedOutput()
	if errRun != nil {
		t.Fatalf("page script does not parse: %v\n%s", errRun, out)
	}
}

func TestUIAuthModuleParses(t *testing.T) {
	nodePath, errLookup := exec.LookPath("node")
	if errLookup != nil {
		t.Skipf("node not available to parse the auth module: %v", errLookup)
	}
	target := filepath.Join(t.TempDir(), "ui_script_auth.js")
	if errWrite := os.WriteFile(target, []byte(uiScriptAuth), 0o600); errWrite != nil {
		t.Fatalf("write auth module: %v", errWrite)
	}
	out, errRun := exec.Command(nodePath, "--check", target).CombinedOutput()
	if errRun != nil {
		t.Fatalf("auth module does not parse: %v\n%s", errRun, out)
	}
}

func TestUIAuthBehaviourHarness(t *testing.T) {
	nodePath, errLookup := exec.LookPath("node")
	if errLookup != nil {
		t.Skipf("node not available for ui_auth behaviour harness: %v", errLookup)
	}
	sourcePath := filepath.Join(t.TempDir(), "ui_script_auth.js")
	if errWrite := os.WriteFile(sourcePath, []byte(uiScriptAuth), 0o600); errWrite != nil {
		t.Fatalf("write auth module: %v", errWrite)
	}
	cmd := exec.Command(nodePath, "ui_auth_harness.mjs", sourcePath)
	cmd.Dir = "."
	out, errRun := cmd.CombinedOutput()
	output := string(out)
	if strings.Contains(output, "not ok -") {
		t.Fatalf("ui_auth behaviour harness reported failures:\n%s", output)
	}
	if errRun != nil {
		t.Fatalf("ui_auth behaviour harness failed: %v\n%s", errRun, output)
	}
	if !strings.Contains(output, "all ui_auth behaviour checks passed") {
		t.Fatalf("ui_auth behaviour harness did not complete:\n%s", output)
	}
}
