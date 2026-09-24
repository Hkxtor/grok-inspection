package main

// uiScriptAuth holds the Management-key resolution, Management API failure
// classification and polling policy used by the UI.
//
// Why this exists: CPA counts every failed Management authentication per client
// IP (including requests without a key). Five failures ban that IP for ~30
// minutes, the ban rejects even the correct key, and 127.0.0.1 is not exempt.
// On a local install the browser, the plugin page and the management panel share
// that IP, so a stale key plus an unattended poll loop locks the operator out of
// the panel itself. Upstream keeps this ban on purpose (issue #4013), so the
// plugin must never guess a key and must stop polling the moment authentication
// fails.
const uiScriptAuth = `  // ---- Management 密钥解析 / 管理鉴权失败分类 / 轮询策略 ----
  const GI_AUTH_STORAGE_KEYS = ['cli-proxy-auth'];
  const GI_LEGACY_STORAGE_KEYS = ['managementKey'];
  const GI_ENC_PREFIX = 'enc::v1::';
  const GI_MAX_KEY_LENGTH = 512;
  const GI_POLL_MS = 1200;
  const GI_BACKOFF_MS = [30000, 60000, 120000];
  let giAuthBlocked = null;
  let giFailureSeq = 0;
  let giBootHydrated = false;
  let giBootRetryTimer = null;
  let giBootRetryCount = 0;

  function giParseJSON(text) {
    try { return JSON.parse(text); } catch (_) { return undefined; }
  }

  // Zustand persist 的载荷可能被多包了一层/两层 JSON 字符串（面板版本差异）。
  function giUnwrapPersisted(raw) {
    let value = String(raw == null ? '' : raw);
    for (let depth = 0; depth < 3; depth++) {
      const parsed = giParseJSON(value);
      if (parsed === undefined) return null;
      if (typeof parsed === 'string') { value = parsed; continue; }
      if (parsed && typeof parsed === 'object') return parsed;
      return null;
    }
    return null;
  }

  // 管理密钥一定是单行纯文本：JSON 片段 / 换行 / 控制字符 / 超长值都是误读，绝不能拿去请求。
  function giLooksLikeManagementKey(value) {
    const key = String(value == null ? '' : value).trim();
    if (!key || key.length > GI_MAX_KEY_LENGTH) return false;
    if (/[\s\u0000-\u001f\u007f]/.test(key)) return false;
    const head = key.charAt(0);
    if (head === '{' || head === '[' || head === '"') return false;
    return true;
  }

  function giFirstManagementKey(candidates) {
    for (let index = 0; index < candidates.length; index++) {
      if (giLooksLikeManagementKey(candidates[index])) return String(candidates[index]).trim();
    }
    return '';
  }

  // payload 已是明文（混淆解码由调用方的 deobfuscatePanelValue 负责）。
  function giKeyFromAuthStorePayload(payload) {
    const store = giUnwrapPersisted(payload);
    if (!store) return '';
    return giFirstManagementKey([
      store.state && store.state.managementKey,
      store.managementKey
    ]);
  }

  function giKeyFromLegacyPayload(payload) {
    const store = giUnwrapPersisted(payload);
    if (!store) {
      // 只有明文旧值才有可能是密钥；带混淆前缀但解不开的内容绝不能拿去请求。
      if (String(payload == null ? '' : payload).indexOf(GI_ENC_PREFIX) === 0) return '';
      return giFirstManagementKey([payload]);
    }
    return giFirstManagementKey([
      store.state && store.state.managementKey,
      store.managementKey,
      store.value,
      store.token
    ]);
  }

  // 解析顺序：官方 cli-proxy-auth（唯一权威）→ 旧版遗留单值键。
  // 官方条目存在且能读懂时它就是权威：即使里面没有密钥（未勾「记住密码」），
  // 也不再回退到可能是陈年旧值的遗留键；只有官方条目缺失/读不懂时才回退。
  function giResolveManagementKey(storage) {
    if (!storage || typeof storage.getItem !== 'function') return '';
    for (let index = 0; index < GI_AUTH_STORAGE_KEYS.length; index++) {
      const raw = storage.getItem(GI_AUTH_STORAGE_KEYS[index]);
      if (!raw) continue;
      const key = giKeyFromAuthStorePayload(deobfuscatePanelValue(raw));
      if (key) return key;
      if (giUnwrapPersisted(deobfuscatePanelValue(raw))) return '';
    }
    for (let index = 0; index < GI_LEGACY_STORAGE_KEYS.length; index++) {
      const raw = storage.getItem(GI_LEGACY_STORAGE_KEYS[index]);
      if (!raw) continue;
      const key = giKeyFromLegacyPayload(deobfuscatePanelValue(raw));
      if (key) return key;
    }
    return '';
  }

  function giManagementError(kind, status, message, retrySeconds) {
    const error = new Error(message);
    error.kind = kind;
    error.status = status;
    error.retrySeconds = retrySeconds || 0;
    return error;
  }

  // CPA 管理鉴权层的失败响应（插件路由同样先过这一层）：
  //   401 {"error":"missing management key"} / {"error":"invalid management key"}
  //   403 {"error":"IP banned due to too many failed attempts. Try again in 14m49s"}
  // 插件业务自身也会返回 403，因此优先按消息判定，避免把业务 403 当成密钥失效。
  function giClassifyManagementFailure(status, body) {
    const code = Number(status) || 0;
    const rawText = String(body == null ? '' : body);
    let message = rawText.trim();
    const parsed = giParseJSON(rawText);
    if (parsed && typeof parsed === 'object') {
      if (typeof parsed.error === 'string') message = parsed.error;
      else if (parsed.error && typeof parsed.error.message === 'string') message = parsed.error.message;
      else if (typeof parsed.message === 'string') message = parsed.message;
    }
    const lower = message.toLowerCase();
    const banned = lower.indexOf('ip banned') >= 0 || lower.indexOf('too many failed attempts') >= 0;
    let retrySeconds = 0;
    if (banned) {
      const match = /try again in\s*(?:(\d+)\s*m)?\s*(\d+)\s*s/i.exec(message);
      if (match) retrySeconds = Number(match[1] || 0) * 60 + Number(match[2] || 0);
    }
    let kind = 'business';
    if (banned) kind = 'banned';
    else if (code === 401 || lower.indexOf('invalid management key') >= 0 || lower.indexOf('missing management key') >= 0) kind = 'invalid_key';
    else if (code === 0) kind = 'network';
    else if (code >= 500) kind = 'server';
    return { kind: kind, status: code, message: message, retrySeconds: retrySeconds };
  }

  function giAuthFailureOf(error) {
    if (error && (error.kind === 'banned' || error.kind === 'invalid_key')) {
      return {
        kind: error.kind,
        status: error.status || 0,
        message: String(error.message || ''),
        retrySeconds: error.retrySeconds || 0
      };
    }
    return null;
  }

  // 鉴权失败必须停表：继续轮询只会继续累加失败次数，把管理面板一起锁掉。
  // 服务端/网络抖动才退避重试，业务错误维持常规节奏。
  function giPollDecision(kind, failureCount) {
    if (kind === 'banned' || kind === 'invalid_key') return { action: 'stop', delayMs: 0 };
    if (kind === 'server' || kind === 'network') {
      const attempt = Math.max(1, Number(failureCount) || 1);
      const index = Math.min(GI_BACKOFF_MS.length - 1, attempt - 1);
      return { action: 'retry', delayMs: GI_BACKOFF_MS[index] };
    }
    return { action: 'retry', delayMs: GI_POLL_MS };
  }

  function giAuthBlockedMessage(failure) {
    if (failure && failure.kind === 'banned') {
      const minutes = failure.retrySeconds ? Math.ceil(failure.retrySeconds / 60) : 0;
      return t('mgmt_banned_prefix') + (minutes ? t('mgmt_banned_about') + minutes + t('mgmt_banned_minutes') : '') + t('mgmt_banned_suffix');
    }
    return t('mgmt_key_invalid');
  }

  // 插件侧缓存的失效密钥需要清掉（继续用同一个值重试没有任何意义）；
  // 管理中心自己的 localStorage 一律不动。
  function forgetStaleManagementKey() {
    try { sessionStorage.removeItem(KEY_STORAGE); } catch (_) {}
    try { localStorage.removeItem(KEY_STORAGE); } catch (_) {}
    try { if (keyInput) keyInput.value = ''; } catch (_) {}
    keySource = 'manual';
    syncKeyHint();
    updateAuthState();
  }

  function giBlockPolling(failure, announce) {
    giAuthBlocked = failure;
    giFailureSeq = 0;
    stopPolling();
    if (failure && failure.kind === 'invalid_key') forgetStaleManagementKey();
    if (announce) showErr(giAuthBlockedMessage(failure));
  }

  function giNoteSuccess() {
    giAuthBlocked = null;
    giFailureSeq = 0;
  }

  function giNoteSoftFailure(kind) {
    giFailureSeq += 1;
    return giPollDecision(kind, giFailureSeq).delayMs;
  }

  function giClearBootRetry() {
    if (giBootRetryTimer != null) {
      clearTimeout(giBootRetryTimer);
      giBootRetryTimer = null;
    }
    giBootRetryCount = 0;
  }

  // 软故障（网络/5xx）下开页加载按退避自动重试；鉴权失败绝不自动重试。
  function giScheduleBootRetry() {
    if (giAuthBlocked) return;
    if (giBootRetryTimer != null) return;
    giBootRetryCount += 1;
    const delayMs = giPollDecision('network', giBootRetryCount).delayMs;
    giBootRetryTimer = setTimeout(() => {
      giBootRetryTimer = null;
      giBootHydrated = false;
      return bootManagementLoad();
    }, delayMs);
  }

  // 开页时只做一次串行加载：第一条 /schedule 同时充当鉴权校验，
  // 通过后才刷新巡检状态与自动禁用列表，避免并发多个管理请求。
  async function bootManagementLoad() {
    if (giBootHydrated) return;
    if (!hasManagementKey()) return;
    giBootHydrated = true;
    const failure = await loadSchedule();
    if (failure) {
      giBootHydrated = false;
      if (failure.auth) { giBlockPolling(failure, true); return; }
      showErr(String(failure.message || ''));
      giScheduleBootRetry();
      return;
    }
    giClearBootRetry();
    await refresh();
    try { await loadBans(); } catch (_) {}
  }

  // 手动改过密钥后允许重新做一次开页加载。
  function giResetBootHydrate() {
    giBootHydrated = false;
    giAuthBlocked = null;
    giClearBootRetry();
  }
`
