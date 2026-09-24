/* ui_auth_harness.mjs — ui_script_auth.go 的 Node 行为测试
 *
 * 由 ui_auth_behavior_test.go 调用：node ui_auth_harness.mjs <ui_script_auth.js 路径>
 * 只验证真实行为（密钥解析、失败分类、停表/退避策略、开页加载顺序），
 * 用桩函数注入 UI 侧依赖，因此不需要浏览器环境。
 * 输出 "ok - <name>" / "not ok - <name>: <detail>"，失败时以非 0 退出。
 */
import fs from 'node:fs';

const sourcePath = process.argv[2];
if (!sourcePath) {
  console.log('not ok - harness: missing ui_script_auth.js path');
  process.exit(1);
}
const source = fs.readFileSync(sourcePath, 'utf8');

let failed = 0;
function check(name, condition, detail) {
  if (condition) {
    console.log('ok - ' + name);
    return;
  }
  failed += 1;
  console.log('not ok - ' + name + ': ' + (detail === undefined ? 'assertion failed' : detail));
}
function equal(name, actual, expected) {
  check(name, actual === expected, 'got ' + JSON.stringify(actual) + ', want ' + JSON.stringify(expected));
}

const HOST = '127.0.0.1:8317';
const UA = 'harness-ua';
const KEY_STORAGE = 'grokInspectionManagementKey';
const ENC_PREFIX = 'enc::v1::';
const SECRET_SALT = 'cli-proxy-api-webui::secure-storage';

function seedBytes() {
  return new TextEncoder().encode(SECRET_SALT + '|' + HOST + '|' + UA);
}
// 与管理中心 src/utils/encryption.ts 的可逆混淆保持一致：面板怎么存，这里就怎么造。
function obfuscate(value) {
  const seed = seedBytes();
  const bytes = new TextEncoder().encode(value);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= seed[index % seed.length];
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return ENC_PREFIX + btoa(binary);
}
function deobfuscatePanelValue(payload) {
  const raw = String(payload == null ? '' : payload);
  if (raw.indexOf(ENC_PREFIX) !== 0) return raw;
  // 与浏览器实现一致：解不开就原样返回（调用方必须自己拒绝密文）。
  try {
    const binary = atob(raw.slice(ENC_PREFIX.length));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const seed = seedBytes();
    for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= seed[index % seed.length];
    return new TextDecoder().decode(bytes);
  } catch (_) {
    return raw;
  }
}
function storage(map) {
  return {
    getItem(key) {
      return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
    },
    removeItem(key) {
      delete map[key];
    }
  };
}
function typedError(kind, status, message, retrySeconds) {
  const error = new Error(message);
  error.kind = kind;
  error.status = status;
  error.retrySeconds = retrySeconds || 0;
  return error;
}
function fakeTimers() {
  const queue = [];
  let seq = 0;
  return {
    setTimeout(fn, delay) {
      seq += 1;
      queue.push({ id: seq, delay: delay, fn: fn });
      return seq;
    },
    clearTimeout(id) {
      const index = queue.findIndex((item) => item.id === id);
      if (index >= 0) queue.splice(index, 1);
    },
    pending() { return queue.map((item) => String(item.delay)); },
    count() { return queue.length; },
    runNext() { const item = queue.shift(); return item ? item.fn() : undefined; }
  };
}
function authStorePayload(key) {
  return JSON.stringify({
    state: { apiBase: 'http://' + HOST, managementKey: key, rememberPassword: true },
    version: 0
  });
}

// 每个场景一份全新的模块实例（模块内部有 giAuthBlocked / giBootHydrated 等状态）。
function loadAuth(options = {}) {
  const localMap = Object.assign({}, options.localStorage || {});
  const sessionMap = Object.assign({}, options.sessionStorage || {});
  const keyInput = { value: Object.prototype.hasOwnProperty.call(options, 'keyInputValue') ? options.keyInputValue : '' };
  const state = {
    stopPolling: 0,
    showErr: [],
    renderSchedule: 0,
    refresh: 0,
    loadBans: 0,
    loadSchedule: 0,
    updateAuthState: 0,
    syncKeyHint: 0,
    apiPaths: [],
    sessionMap: sessionMap,
    localMap: localMap,
    keyInput: keyInput
  };
  const stubAPI = options.api || (async () => ({}));
  // loadSchedule 在另一个脚本块里，这里用桩函数替代：真实实现用 api('/schedule')
  // 做鉴权校验（由 Go 侧契约测试 tl' 住），本文件验证 bootManagementLoad 的控制流。
  const scenario = { failure: options.scheduleFailure || null };
  const stubLoadSchedule = options.loadSchedule || (async () => {
    state.loadSchedule += 1;
    return typeof scenario.failure === 'function' ? scenario.failure() : scenario.failure;
  });
  const timers = options.timers || null;
  const deps = {
    t: (key) => key,
    stopPolling: () => { state.stopPolling += 1; },
    showErr: (message) => { state.showErr.push(String(message)); },
    updateAuthState: () => { state.updateAuthState += 1; },
    syncKeyHint: () => { state.syncKeyHint += 1; },
    deobfuscatePanelValue: deobfuscatePanelValue,
    keyInput: keyInput,
    keySource: 'manual',
    KEY_STORAGE: KEY_STORAGE,
    setTimeout: timers ? timers.setTimeout : globalThis.setTimeout,
    clearTimeout: timers ? timers.clearTimeout : globalThis.clearTimeout,
    api: async (path, opts) => {
      state.apiPaths.push(path);
      return stubAPI(path, opts);
    },
    refresh: async () => { state.refresh += 1; },
    loadBans: async () => { state.loadBans += 1; },
    loadSchedule: stubLoadSchedule,
    renderSchedule: () => { state.renderSchedule += 1; },
    hasManagementKey: () => !!String(keyInput.value || '').trim(),
    sessionStorage: storage(sessionMap),
    localStorage: storage(localMap)
  };
  const names = Object.keys(deps);
  const exported = `\n;return {giResolveManagementKey: giResolveManagementKey, giLooksLikeManagementKey: giLooksLikeManagementKey,` +
    ` giClassifyManagementFailure: giClassifyManagementFailure, giPollDecision: giPollDecision,` +
    ` giBlockPolling: giBlockPolling, giNoteSuccess: giNoteSuccess, bootManagementLoad: bootManagementLoad, giResetBootHydrate: giResetBootHydrate,` +
    ` giAuthFailureOf: giAuthFailureOf, giManagementError: giManagementError,` +
    ` giAuthBlockedKind: function () { return giAuthBlocked && giAuthBlocked.kind; }};`;
  // eslint-disable-next-line no-new-func
  const factory = new Function(...names, source + exported);
  const module = factory(...names.map((name) => deps[name]));
  return { module: module, state: state, keyInput: keyInput, scenario: scenario };
}

// --- 密钥解析 ---------------------------------------------------------------
{
  const cases = [
    ['official store (obfuscated) resolves key', obfuscate(authStorePayload('mgmt-key-official')), 'mgmt-key-official'],
    ['official store (plaintext json) resolves key', authStorePayload('mgmt-key-plain'), 'mgmt-key-plain'],
    ['official store with double-encoded payload resolves key', obfuscate(JSON.stringify(authStorePayload('mgmt-key-double'))), 'mgmt-key-double'],
    ['undecodable ciphertext is rejected', ENC_PREFIX + '###not-base64###', ''],
    ['key-less store object is rejected', obfuscate(JSON.stringify({ state: { apiBase: 'http://x' }, version: 0 })), '']
  ];
  for (const [name, raw, expected] of cases) {
    const env = loadAuth({ localStorage: { 'cli-proxy-auth': raw } });
    equal(name, env.module.giResolveManagementKey(storage({ 'cli-proxy-auth': raw })), expected);
  }
  const legacy = loadAuth({ localStorage: { managementKey: 'legacy-key' } });
  equal('legacy single-value store resolves key', legacy.module.giResolveManagementKey(storage({ managementKey: 'legacy-key' })), 'legacy-key');
  const brokenLegacy = loadAuth({});
  equal('undecodable legacy ciphertext is rejected', brokenLegacy.module.giResolveManagementKey(storage({ managementKey: ENC_PREFIX + 'junk!!' })), '');
  // 官方条目能读懂但里面没有密钥（未勾「记住密码」）时它就是权威：
  // 不回退到陈年旧值，以免拿过期密钥去烧失败次数。
  equal(
    'key-less official store suppresses the legacy fallback',
    brokenLegacy.module.giResolveManagementKey(storage({
      'cli-proxy-auth': obfuscate(JSON.stringify({ state: { apiBase: 'http://x', rememberPassword: false }, version: 0 })),
      managementKey: 'stale-legacy-key'
    })),
    ''
  );
  equal(
    'unreadable official store still allows the legacy fallback',
    brokenLegacy.module.giResolveManagementKey(storage({ 'cli-proxy-auth': ENC_PREFIX + '###broken###', managementKey: 'legacy-migrated-key' })),
    'legacy-migrated-key'
  );
  const wrongKeyName = loadAuth({ localStorage: { CPA_MANAGEMENT_KEY: 'guess-key' } });
  equal('guessed storage names are no longer read', wrongKeyName.module.giResolveManagementKey(storage({ CPA_MANAGEMENT_KEY: 'guess-key' })), '');
  const empty = loadAuth({});
  equal('empty storage resolves to empty key', empty.module.giResolveManagementKey(storage({})), '');

  const guard = loadAuth({});
  equal('multiline value rejected', guard.module.giLooksLikeManagementKey('a\nb'), false);
  equal('oversized value rejected', guard.module.giLooksLikeManagementKey('k'.repeat(513)), false);
  equal('json blob rejected', guard.module.giLooksLikeManagementKey('{"state":{}}'), false);
  equal('trimmed key accepted', guard.module.giLooksLikeManagementKey('  mgmt-key  '), true);
}

// --- 失败分类 ---------------------------------------------------------------
{
  const env = loadAuth({});
  const classify = env.module.giClassifyManagementFailure;
  const invalid = classify(401, JSON.stringify({ error: 'invalid management key' }));
  check('401 invalid management key classified', invalid.kind === 'invalid_key', JSON.stringify(invalid));
  const missing = classify(401, JSON.stringify({ error: 'missing management key' }));
  check('401 missing management key classified', missing.kind === 'invalid_key', JSON.stringify(missing));
  const banned = classify(403, JSON.stringify({ error: 'IP banned due to too many failed attempts. Try again in 14m49s' }));
  check('403 ban classified', banned.kind === 'banned', JSON.stringify(banned));
  equal('ban countdown parsed', banned.retrySeconds, 14 * 60 + 49);
  const business = classify(403, '权限拒绝');
  check('plugin business 403 is not an auth failure', business.kind === 'business', JSON.stringify(business));
  check('500 classified as server', classify(500, 'boom').kind === 'server');
  check('transport failure classified as network', classify(0, '').kind === 'network');
  check('auth failure helper only matches auth kinds', env.module.giAuthFailureOf(typedError('banned', 403, 'x', 5)) !== null &&
    env.module.giAuthFailureOf(typedError('business', 403, 'x')) === null);
}

// --- 轮询策略 ---------------------------------------------------------------
{
  const env = loadAuth({});
  const decide = env.module.giPollDecision;
  check('banned stops polling', decide('banned', 3).action === 'stop');
  check('invalid_key stops polling', decide('invalid_key', 1).action === 'stop');
  equal('server failure backs off 30s', decide('server', 1).delayMs, 30000);
  equal('second server failure backs off 60s', decide('server', 2).delayMs, 60000);
  equal('third server failure backs off 120s', decide('server', 3).delayMs, 120000);
  equal('backoff is capped', decide('network', 7).delayMs, 120000);
  equal('business failure keeps poll cadence', decide('business', 1).delayMs, 1200);
}

// --- 熔断行为 ---------------------------------------------------------------
{
  // 密钥失效：停表 + 清掉插件侧缓存的失效密钥，但不动管理中心的存储。
  const env = loadAuth({ sessionStorage: { [KEY_STORAGE]: 'stale-key' }, keyInputValue: 'stale-key', localStorage: { 'cli-proxy-auth': 'panel-value' } });
  env.module.giBlockPolling({ kind: 'invalid_key', status: 401, message: 'invalid management key', retrySeconds: 0 }, true);
  check('invalid_key stops polling', env.state.stopPolling === 1);
  equal('invalid_key clears plugin cached key', env.state.sessionMap[KEY_STORAGE], undefined);
  equal('invalid_key clears the key input', env.keyInput.value, '');
  equal('invalid_key keeps the panel storage untouched', env.state.localMap['cli-proxy-auth'], 'panel-value');
  check('invalid_key announces recovery hint', env.state.showErr.length === 1 && env.state.showErr[0] === 'mgmt_key_invalid', JSON.stringify(env.state.showErr));
  equal('blocked state remembered', env.module.giAuthBlockedKind(), 'invalid_key');

  // 本机被封：停表 + 提示剩余分钟，但保留密钥（密钥可能是对的）。
  const bannedEnv = loadAuth({ keyInputValue: 'good-key' });
  bannedEnv.module.giBlockPolling({ kind: 'banned', status: 403, message: 'IP banned', retrySeconds: 889 }, true);
  check('banned stops polling', bannedEnv.state.stopPolling === 1);
  equal('banned keeps the key input', bannedEnv.keyInput.value, 'good-key');
  const message = bannedEnv.state.showErr[0] || '';
  check('banned message carries remaining minutes', message.indexOf('mgmt_banned_prefix') === 0 && message.indexOf('mgmt_banned_minutes') > 0 && message.indexOf('15') > 0, message);
}

// --- 开页加载控制流（loadSchedule 以桩函数驱动） ---------------------------
{
  const env = loadAuth({ keyInputValue: 'good-key' });
  await env.module.bootManagementLoad();
  equal('successful boot validates first', env.state.loadSchedule, 1);
  equal('successful boot refreshes status once', env.state.refresh, 1);
  equal('successful boot loads bans once', env.state.loadBans, 1);
  equal('successful boot keeps polling allowed', env.state.stopPolling, 0);
  await env.module.bootManagementLoad();
  equal('boot is idempotent (no duplicate request burst)', env.state.loadSchedule + env.state.refresh + env.state.loadBans, 3);
}

{
  const env = loadAuth({
    keyInputValue: 'good-key',
    scheduleFailure: { kind: 'banned', status: 403, message: 'IP banned', retrySeconds: 889, auth: true }
  });
  await env.module.bootManagementLoad();
  equal('banned boot stops polling', env.state.stopPolling, 1);
  equal('banned boot does not continue loading', env.state.refresh + env.state.loadBans + env.state.renderSchedule, 0);
  check('banned boot surfaces the ban hint', (env.state.showErr[0] || '').indexOf('mgmt_banned_prefix') === 0, JSON.stringify(env.state.showErr));
}

{
  const timers = fakeTimers();
  const env = loadAuth({
    keyInputValue: 'good-key',
    timers: timers,
    scheduleFailure: { kind: 'network', status: 0, message: 'dial tcp: refused', retrySeconds: 0, auth: false }
  });
  await env.module.bootManagementLoad();
  equal('soft boot failure does not stop polling permanently', env.state.stopPolling, 0);
  equal('soft boot failure is reported as-is', env.state.showErr[0], 'dial tcp: refused');
  equal('soft boot failure does not continue loading', env.state.refresh + env.state.loadBans, 0);
  equal('soft boot failure arms one retry timer', timers.pending().join(','), '30000');
}

{
  const env = loadAuth({
    keyInputValue: 'good-key',
    scheduleFailure: { kind: 'invalid_key', status: 401, message: 'invalid management key', retrySeconds: 0, auth: true }
  });
  await env.module.bootManagementLoad();
  equal('invalid key boot stops polling', env.state.stopPolling, 1);
  equal('invalid key boot does not continue loading', env.state.refresh + env.state.loadBans, 0);
  equal('invalid key boot announces once', env.state.showErr.length, 1);
  env.state.loadSchedule = 0;
  env.keyInput.value = 'fresh-key';
  env.module.giResetBootHydrate();
  await env.module.bootManagementLoad();
  equal('manual key reset re-runs the validation step', env.state.loadSchedule, 1);
}

{
  const env = loadAuth({ keyInputValue: '' });
  await env.module.bootManagementLoad();
  equal('boot without a key sends no management request', env.state.apiPaths.length, 0);
  equal('boot without a key does not refresh', env.state.refresh + env.state.loadSchedule, 0);
}

// --- 软故障退避重试与熔断解除（假定时器） ----------------------------------
{
  const timers = fakeTimers();
  const env = loadAuth({
    keyInputValue: 'good-key',
    timers: timers,
    scheduleFailure: { kind: 'network', status: 0, message: 'dial tcp: refused', retrySeconds: 0, auth: false }
  });
  await env.module.bootManagementLoad();
  equal('soft boot failure arms a backoff retry', timers.pending().join(','), '30000');
  env.scenario.failure = null;
  await timers.runNext();
  equal('boot retry validates again', env.state.loadSchedule, 2);
  equal('boot retry continues loading after success', env.state.refresh + env.state.loadBans, 2);
  equal('no retry timer left after success', timers.count(), 0);
}

{
  const timers = fakeTimers();
  const env = loadAuth({
    keyInputValue: 'good-key',
    timers: timers,
    scheduleFailure: { kind: 'banned', status: 403, message: 'IP banned', retrySeconds: 889, auth: true }
  });
  await env.module.bootManagementLoad();
  equal('auth failure never arms a boot retry', timers.count(), 0);
  equal('auth failure stops polling', env.state.stopPolling, 1);
}

{
  const env = loadAuth({});
  env.module.giBlockPolling({ kind: 'banned', status: 403, message: 'IP banned', retrySeconds: 60 }, false);
  equal('blocked state before recovery', env.module.giAuthBlockedKind(), 'banned');
  env.module.giNoteSuccess();
  equal('successful refresh clears the block', env.module.giAuthBlockedKind(), null);
}

if (failed > 0) {
  console.log('failed: ' + failed);
  process.exit(1);
}
console.log('all ui_auth behaviour checks passed');
