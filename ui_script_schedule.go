package main

const uiScriptSchedule = `  const classLabel = {
    healthy: t('class_healthy'), permission_denied: t('class_permission_denied'), quota_exhausted: t('class_quota_exhausted'), spending_limit: t('class_spending_limit'),
    reauth: t('class_reauth'), model_unavailable: t('class_model_unavailable'), probe_error: t('class_probe_error'), unknown: t('class_unknown')
  };
  const actionLabel = { keep: t('action_keep'), disable: t('action_disable'), enable: t('action_enable'), delete: t('action_delete') };
  const color = {
    healthy: '#047857', permission_denied: '#b45309', quota_exhausted: '#b45309', spending_limit: '#c2410c',
    reauth: '#b91c1c', model_unavailable: '#475569', probe_error: '#b91c1c', unknown: '#475569'
  };
  function pill(text, c) {
    return '<span class="badge pill" style="background:' + c + '1a;color:' + c + '">' + escapeHtml(text) + '</span>';
  }
  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  }
  const esc = escapeHtml;
  async function api(path, opts) {
    const key = String(keyInput.value || '').trim();
    if (!key) {
      // 没有密钥就绝不发请求：CPA 会把每次无密钥的管理访问也计成一次失败，
      // 连续 5 次即临时封禁本机 IP（封禁期间密钥正确也会被拒）。
      throw giManagementError('invalid_key', 0, t('need_key'));
    }
    // 管理路由必须带密钥；不再依赖浏览器缓存里的旧值做“隐式”尝试。
    const headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key };
    let res;
    try {
      res = await fetch(BASE + path, Object.assign({ headers }, opts || {}));
    } catch (networkError) {
      throw giManagementError('network', 0, String((networkError && networkError.message) || networkError));
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = { raw: text }; }
    // 202 Accepted is success for async apply/action
    if (!res.ok) {
      const failure = giClassifyManagementFailure(res.status, text);
      // 鉴权失败立刻停表：继续轮询只会继续累加失败次数，把管理面板一起锁掉。
      if (failure.kind === 'banned' || failure.kind === 'invalid_key') giBlockPolling(failure, false);
      throw giManagementError(failure.kind, res.status, (data && (data.error || data.message)) || text || ('HTTP ' + res.status), failure.retrySeconds);
    }
    return data;
  }
  let scheduleDirty = false;
  function scheduleStatusText(data) {
    if (!data || typeof data !== 'object') return t('schedule_loading');
    if (data.enabled === false) return t('schedule_disabled');
    const status = String(data.last_status || 'waiting');
    let text = status === 'running' ? t('schedule_running')
      : status === 'completed' ? t('schedule_completed')
      : status === 'failed' ? t('schedule_failed')
      : status === 'stopped' ? t('schedule_stopped')
      : status === 'action_failed' ? t('schedule_action_failed')
      : status === 'completed_with_errors' ? t('schedule_completed_errors')
      : status === 'skipped' ? t('schedule_skipped')
      : t('schedule_waiting');
    if (data.last_run_at) text += ' · ' + t('schedule_last') + formatShanghaiTime(data.last_run_at);
    if (data.next_run_at) text += ' · ' + t('schedule_next') + formatShanghaiTime(data.next_run_at);
    if (Number(data.last_matched || 0) > 0) {
      const matched403 = Number(data.last_matched_403 || 0);
      const matched402 = Number(data.last_matched_402 || 0);
      const matched429 = Number(data.last_matched_429 || 0);
      const matched401 = Number(data.last_matched_401 || 0);
      const matchedRecover = Number(data.last_matched_recover || 0);
      if (matched429 > 0) {
        text += ' · ' + t('schedule_counts_429') + matched429;
        text += t('schedule_disabled_count') + (data.last_disabled_429 || 0);
        text += t('schedule_failed_count') + (data.last_failed_429 || 0);
      }
      if (matched401 > 0) {
        text += ' · ' + t('schedule_counts_401') + matched401;
        text += t('schedule_disabled_count') + (data.last_disabled_401 || 0);
        text += t('schedule_failed_count') + (data.last_failed_401 || 0);
      }
      if (matched403 > 0) {
        text += ' · ' + t('schedule_counts') + matched403;
        text += t('schedule_disabled_count') + (data.last_disabled_403 || 0);
        text += t('schedule_deleted_count') + (data.last_deleted_403 || 0);
        text += t('schedule_failed_count') + (data.last_failed_403 || 0);
      }
      if (matched402 > 0) {
        text += ' · ' + t('schedule_counts_402') + matched402;
        text += t('schedule_disabled_count') + (data.last_disabled_402 || 0);
        text += t('schedule_deleted_count') + (data.last_deleted_402 || 0);
        text += t('schedule_failed_count') + (data.last_failed_402 || 0);
      }
      if (matchedRecover > 0) {
        text += ' · ' + t('schedule_recovered_count') + (data.last_recovered || 0);
        text += t('schedule_failed_count') + (data.last_failed_recover || 0);
      }
      if (matched403 === 0 && matched402 === 0 && matched429 === 0 && matched401 === 0 && matchedRecover === 0) {
        text += ' · ' + t('schedule_counts') + data.last_matched;
        text += t('schedule_disabled_count') + (data.last_disabled || 0);
        text += t('schedule_deleted_count') + (data.last_deleted || 0);
        text += t('schedule_failed_count') + (data.last_failed || 0);
      }
    }

    if (data.action_ready === false) text += ' · ' + t('schedule_key_missing');
    if (data.last_error) text += ' · ' + data.last_error;
    return text;
  }
  // Sample scope reuses the toolbar sample count/percent instead of a second copy.
  function syncScheduleScopeFields() {
    const sample = $('scheduleScope') && $('scheduleScope').value === 'sample';
    const row = $('samplingRow');
    if (row) row.classList.toggle('schedule-linked', !!sample);
  }
  function renderSchedule(data, hydrate) {
    if (!data || typeof data !== 'object') return;
    if (hydrate && !scheduleDirty) {
      $('scheduleEnabled').checked = !!data.enabled;
      $('scheduleInterval').value = String(data.interval_minutes || 60);
      $('scheduleWorkers').value = String(clampWorkers(Number(data.workers) || WORKERS_DEFAULT));
      $('scheduleIncludeDisabled').checked = !!data.include_disabled;
      $('scheduleOnlyDisabled').checked = !!data.only_disabled;
      if ($('scheduleOnlyDisabled').checked) $('scheduleIncludeDisabled').checked = false;
      $('scheduleScope').value = data.scope === 'sample' ? 'sample' : 'full';
      if (data.scope === 'sample') {
        // Only seed empty toolbar inputs so a saved schedule never clobbers local edits.
        if (data.sample_count && !$('sampleCount').value) $('sampleCount').value = String(data.sample_count);
        if (data.sample_percent && !$('samplePercent').value) $('samplePercent').value = String(data.sample_percent);
      }
      syncScheduleScopeFields();
      $('schedule403Action').value = data.permission_denied_action === 'delete' ? 'delete' : 'disable';
      $('schedule402Action').value = data.spending_limit_action === 'delete' ? 'delete' : 'disable';
      if ($('scheduleAutoRecoverHealthy')) $('scheduleAutoRecoverHealthy').checked = !!data.auto_recover_healthy;
    }
    const status = $('scheduleStatus');
    if (status) status.textContent = scheduleStatusText(data);
    const save = $('scheduleSaveBtn');
    if (save) save.disabled = !hasManagementKey();
  }
  // 返回 null 表示成功；否则返回失败描述（供开页流程判断是否继续加载）。
  async function loadSchedule() {
    if (!hasManagementKey()) {
      renderSchedule({ enabled: false, action_ready: false }, true);
      return null;
    }
    try {
      const raw = await api('/schedule');
      const data = (raw && raw.result && typeof raw.result === 'object') ? raw.result : raw;
      renderSchedule(data, true);
      giNoteSuccess();
      return null;
    } catch (e) {
      const failure = giAuthFailureOf(e);
      if (failure) {
        // 鉴权失败：先停表（提示交给调用方，避免同一条消息弹两次）。
        giBlockPolling(failure, false);
        return failure;
      }
      const status = $('scheduleStatus');
      if (status) status.textContent = String(e.message || e);
      return { kind: (e && e.kind) || 'error', status: 0, message: String((e && e.message) || e), retrySeconds: 0, auth: false };
    }
  }
  async function saveSchedule() {
    if (!hasManagementKey()) {
      showErr(t('need_key'));
      return;
    }
    const enabled = $('scheduleEnabled').checked;
    const interval = Number($('scheduleInterval').value);
    const workers = Number($('scheduleWorkers').value);
    if (!Number.isInteger(interval) || interval < SCHEDULE_INTERVAL_MIN || interval > SCHEDULE_INTERVAL_MAX) {
      showErr(t('schedule_interval') + ': ' + SCHEDULE_INTERVAL_MIN + '-' + SCHEDULE_INTERVAL_MAX);
      return;
    }
    if (!Number.isInteger(workers) || workers < WORKERS_MIN || workers > WORKERS_MAX) {
      showErr(t('workers_range_prefix') + WORKERS_MIN + '-' + WORKERS_MAX + t('workers_range_suffix'));
      return;
    }
    const scope = $('scheduleScope').value === 'sample' ? 'sample' : 'full';
    let sampleCount = 0;
    let samplePercent = 0;
    if (scope === 'sample') {
      let sample;
      try {
        sample = parseSampleInputs();
      } catch (e) {
        showErr(String(e.message || e));
        return;
      }
      if (!sample.count && !sample.percent) {
        showErr(t('sample_need_params'));
        return;
      }
      saveSamplePrefs(sample);
      sampleCount = sample.count;
      samplePercent = sample.percent;
    }
    const action = $('schedule403Action').value === 'delete' ? 'delete' : 'disable';
    const action402 = $('schedule402Action').value === 'delete' ? 'delete' : 'disable';
    if (action === 'delete' || action402 === 'delete') {
      const only402Delete = action !== 'delete' && action402 === 'delete';
      const bothDelete = action === 'delete' && action402 === 'delete';
      const ok = await confirmDialog(
        bothDelete ? t('schedule_both_delete_confirm_title') : (only402Delete ? t('schedule_402_delete_confirm_title') : t('schedule_delete_confirm_title')),
        bothDelete ? t('schedule_both_delete_confirm_body') : (only402Delete ? t('schedule_402_delete_confirm_body') : t('schedule_delete_confirm_body'))
      );
      if (!ok) return;
    }
    const btn = $('scheduleSaveBtn');
    if (btn) btn.disabled = true;
    try {
      const raw = await api('/schedule', {
        method: 'POST',
        body: JSON.stringify({
          enabled,
          interval_minutes: interval,
          workers,
          include_disabled: $('scheduleIncludeDisabled').checked,
          only_disabled: $('scheduleOnlyDisabled').checked,
          scope,
          sample_count: sampleCount,
          sample_percent: samplePercent,
          permission_denied_action: action,
          spending_limit_action: action402,
          auto_recover_healthy: !!( $('scheduleAutoRecoverHealthy') && $('scheduleAutoRecoverHealthy').checked )
        })
      });
      const data = (raw && raw.result && typeof raw.result === 'object') ? raw.result : raw;
      scheduleDirty = false;
      renderSchedule(data, true);
      showOk(t('schedule_saved'));
    } catch (e) {
      const failure = giAuthFailureOf(e);
      if (failure) giBlockPolling(failure, true);
      else showErr(String(e.message || e));
      if (btn) btn.disabled = false;
    }
  }
`
