package main

const uiScriptPoll = `  let pollTimer = null;
  let pollInFlight = false;
  let pollDelayMs = 0;
  const POLL_MS = 1200;
  // Full results are heavy at 1000+ accounts; keep light polls frequent, full list rarer while running.
  const LIVE_RESULTS_MS = 10000;
  const LIVE_RESULTS_IDLE_MS = 2400;
  let lastJobBusy = false;
  let lastResultsGen = 0;
  let lastFullResultsAt = 0;
  let fullResultsSyncing = false;
  function stopPolling() {
    if (pollTimer != null) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  }
  // 自调度轮询：同一时刻只允许一个请求在飞；
  // 识别到鉴权失败（giAuthBlocked）后永不重新起表，直到成功刷新过一次。
  function startPolling() {
    if (giAuthBlocked) { stopPolling(); return; }
    if (pollTimer != null) return;
    const delayMs = pollDelayMs > 0 ? pollDelayMs : POLL_MS;
    pollDelayMs = 0;
    pollTimer = setTimeout(pollTick, delayMs);
  }
  async function pollTick() {
    pollTimer = null;
    if (giAuthBlocked) return;
    if (confirmOpen) { startPolling(); return; } // modal open: keep UI responsive for cancel/ok
    if (pollInFlight) { startPolling(); return; }
    pollInFlight = true;
    try {
      // Light polls omit results[] — progress only.
      await refresh({ light: true });
    } finally {
      pollInFlight = false;
    }
  }
  // Only poll while a server job is active; idle pages do not keep hitting /status.
  function syncPolling(snap) {
    if (giAuthBlocked) { stopPolling(); return; }
    const unbanRun = !!(snap && snap.unban && snap.unban.running);
    if (snap && (snap.running || snap.applying || unbanRun)) startPolling();
    else stopPolling();
  }
  function mergeLightStatus(data) {
    const prev = state.snapshot || {};
    // Keep local results during light poll; refresh meta/progress only.
    state.snapshot = Object.assign({}, prev, data || {}, {
      results: prev.results || [],
      include_results: false
    });
  }
  async function syncFullResults(force, busyRunning) {
    if (fullResultsSyncing) return false;
    const minGap = busyRunning ? LIVE_RESULTS_MS : LIVE_RESULTS_IDLE_MS;
    if (!force && Date.now() - lastFullResultsAt < minGap) return false;
    fullResultsSyncing = true;
    try {
      await refresh({ light: false });
      return true;
    } finally {
      lastFullResultsAt = Date.now();
      fullResultsSyncing = false;
    }
  }
  async function refresh(opts) {
    const light = !!(opts && opts.light);
    if (!keyInput.value.trim()) {
      stopPolling();
      state.snapshot = { results: [], summary: {}, running: false, applying: false, done: 0, total: 0 };
      if ($('error').className === 'err') $('error').textContent = '';
      updateAuthState();
      render();
      return;
    }
    try {
      const path = (light ? '/status?include_results=0' : '/status?include_results=1') + '&lang=' + encodeURIComponent(lang);
      const data = await api(path, { method: 'GET' });
      const busy = !!(data && (data.running || data.applying || (data.unban && data.unban.running)));
      const wasBusy = lastJobBusy;
      lastJobBusy = busy;

      if (light) {
        mergeLightStatus(data);
      } else {
        state.snapshot = data || {};
        if (data && data.results_gen != null) lastResultsGen = Number(data.results_gen) || 0;
        lastFullResultsAt = Date.now();
      }
      if (data && data.schedule) renderSchedule(data.schedule, false);

      if (data && data.running) {
        $('includeDisabled').checked = !!data.include_disabled;
        $('onlyDisabled').checked = !!data.only_disabled;
        if (data.workers) $('workers').value = String(clampWorkers(Number(data.workers) || WORKERS_DEFAULT));
      }
      // Do not wipe success toasts; only clear stale red errors when server is clean.
      if (!(data.apply_failures || []).length && pendingOps.size === 0 && $('error').className === 'err') {
        $('error').textContent = '';
      }
      // 先清熔断状态，再让 syncPolling 决定是否继续轮询：
      // 反过来写会让「封禁解除后手动刷新成功」无法重新起表。
      giNoteSuccess();
      syncPolling(data);
      // Avoid expensive table re-render under an open modal (cancel feels stuck).
      if (!confirmOpen) render();
      else {
        // Still keep progress text cheaply updated.
        try {
          const snap = state.snapshot || {};
          if (snap.running || snap.applying) {
            // progress only path inside render is heavy; update line directly
            if (snap.applying) {
              setProgress(t('apply_progress') + (snap.apply_done||0) + '/' + (snap.apply_total||0), true);
            } else if (snap.running) {
              setProgress(t('inspect_running') + ' ' + (snap.done||0) + '/' + (snap.total||0), true);
            }
          }
        } catch (_) {}
      }

      // Job just finished → pull full results once (list may have changed a lot).
      if (wasBusy && !busy) {
        await syncFullResults(true, false);
        if (hasManagementKey()) { try { await loadBans(); } catch (_) {} }
        return;
      }
      // Keep the account table live during inspection without sending the full
      // 1000+ row payload on every progress poll.
      if (light && data && data.results_gen != null) {
        const gen = Number(data.results_gen) || 0;
        if (gen && gen !== lastResultsGen) {
          // While inspecting, throttle full list pulls; still force when job ends (wasBusy path).
          const synced = await syncFullResults(!busy, !!(data && (data.running || data.applying || (data.unban && data.unban.running))));
          if (synced) lastResultsGen = gen;
          if (synced) return;
        }
      }
    } catch (e) {
      const failure = giAuthFailureOf(e);
      if (failure) {
        // 鉴权失败：停表 + 提示，绝不再自动重试。
        giBlockPolling(failure, true);
        return;
      }
      showErr(String(e.message || e));
      // 服务端/网络抖动只做退避，不当作密钥问题；仍认为任务在跑才继续。
      pollDelayMs = giNoteSoftFailure((e && e.kind) || 'network');
      syncPolling(state.snapshot);
    }
  }
`
