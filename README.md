# Grok Inspection

> **中文** | [English](README.en.md)

CPA（CLIProxyAPI）插件：批量检测 xAI / Grok 账号健康状态，并给出禁用 / 启用 / 删除建议。

## 说明

这是一个 **纯 vibe coding** 产物：功能能跑、够用，但代码风格、结构和边界细节未必按传统工程规范打磨。

- **欢迎提 Issue / PR**：修 bug、补能力、改体验、重构都欢迎。
- **如果你介意 vibe coding**：不必强用本插件，可以直接用 **CPA Manager Plus** 等管理面板里更完整的账号巡检 / 运维能力作为替代。
- 本插件定位是轻量、**可选**的 Grok/xAI 巡检补充，不是官方标准实现。

版本：`0.1.22` · 菜单：**Grok 账号巡检**

## 语言
管理界面支持 **中英双语切换**：
- **中文（默认）** — 本项目的第一语言
- **English** — 页面顶部 **语言 / Language** 选择器可切换
- 选择会保存在 `localStorage`（键名 `grok-inspection.lang`），刷新后恢复
- 开始巡检时会把所选 `lang` 传给后端，使原因/错误文案与界面语言一致
English docs: [README.en.md](README.en.md).
## 功能

- 完整巡检、增量巡检、按分类重巡 Grok/xAI 账号
- 抽检：按数量或比例随机检测，未抽中账号保留原有结果
- 支持自动巡检，可配置间隔、并发、巡检范围（全量/抽检）、是否包含已禁用账号及 402/403 后续禁用或删除
- 自动巡检选择抽检时沿用工具条的抽检数量与比例，自动处置只作用于本轮实际探测到的账号
- 识别健康、402 额度/订阅受限、权限被拒、额度用尽、需重新登录、模型不可用、探测异常
- 后台执行巡检和批量操作，切换页面不丢任务
- 支持一键执行建议、批量禁用、批量删除、单账号处理
- 巡检结果会自动保存，页面重新打开后可恢复
- 支持导出当前筛选结果为 JSON/TXT
- 实时自动禁用（默认开启）：额度用尽 24h 后自动恢复；402/403/401 需手动解禁

## 安装

从 [Releases](https://github.com/Hkxtor/grok-inspection/releases) 下载与你的 CPA 平台匹配的压缩包：

| 平台 | 文件 |
|------|------|
| Linux amd64 | `grok-inspection_*_linux_amd64.zip` |
| Linux arm64 | `grok-inspection_*_linux_arm64.zip` |
| FreeBSD amd64 | `grok-inspection_*_freebsd_amd64.zip` |
| Windows amd64 | `grok-inspection_*_windows_amd64.zip` |
| macOS arm64 | `grok-inspection_*_darwin_arm64.zip` |

解压后把插件文件放到 CPA 插件目录：

```text
grok-inspection.so      # Linux
grok-inspection.dll     # Windows
grok-inspection.dylib   # macOS
```

在 CPA 配置中启用插件：

```yaml
plugins:
  enabled: true
  configs:
    grok-inspection:
      enabled: true
      priority: 1
```

重启 CPA 后，在管理页面打开 **Grok 账号巡检**，输入 CPA Management Key 即可使用。

> 同源部署下页面会自动复用管理中心保存的 Key，不必手填；密钥复用与「本机临时封禁」的细节见下方 [管理密钥与临时封禁](#管理密钥与临时封禁)。

## Docker

如果 CPA 运行在 Docker 中，把插件拷到容器内的插件目录后重启容器。容器名和插件路径以你的实际环境为准，例如：

```bash
docker cp ./grok-inspection.so <容器名>:<插件目录>/grok-inspection.so
docker restart <容器名>
```

删除 / 禁用账号时，会使用页面里填写的 CPA Management Key。

插件默认通过本机回环地址调用 CPA Management API。在 Docker、端口映射或自定义监听端口环境中，如果插件无法访问实际管理端口，请在 CPA 进程中显式设置：

```bash
CPA_MANAGEMENT_BASE_URL=http://127.0.0.1:<实际端口>
```

启用 TLS 时使用 `https://`。显式配置后，请求失败也不会回退到浏览器请求的 Origin。

## 管理密钥与临时封禁

页面优先从管理中心的同源 `localStorage`（`cli-proxy-auth`，官方 `enc::v1::` 混淆格式）自动读取 Management Key，只有读不到时才需要手填；管理中心未勾选「记住密码」时页面不会自动取到 Key。

CPA 对**任意管理路由**（包括插件自身的 `/v0/management/...`）在鉴权层按客户端 IP 计数失败：连续 5 次失败即临时封禁该 IP 约 30 分钟，**封禁期间密钥正确也会被拒**，且 `127.0.0.1` 同样会被封。本机部署时浏览器、插件页与管理台共用同一个 IP，所以「密钥过期 + 后台定时轮询」会把管理台一起锁死（管理台报 `IP banned due to too many failed attempts. Try again in …`）。该策略是 CPA 有意的安全行为（上游 issue #4013 明确不会放宽），插件侧只能保证不去制造失败次数。

当前行为：

- 只读官方 `cli-proxy-auth`（兼容单/双次 JSON 包裹），并保留对面板旧版单值键 `managementKey` 的兼容；历史版本猜测过的 `authToken`、`cli-proxy-management-key`、`management_password` 等键名已不再读取（如果你之前把手填的 Key 放在这些键名里，请在插件页输入框重新填写一次，会保存在当前标签会话中）；读到 JSON 片段 / 换行 / 超长值 / 解不开的密文一律视为「没有 Key」，**不发请求**
- 开页只发一条 `/schedule` 做鉴权校验，通过后才刷新巡检状态与自动禁用列表；轮询改为自调度，同一时刻只有一个请求在飞
- 识别到 `invalid management key` / `missing management key` / `IP banned …` 时立即**停止轮询**：密钥失效会清掉插件侧缓存并提示重新登录；本机被封只提示剩余时间（保留已填写的 Key）
- 5xx 与网络错误只做 30s / 60s / 120s 退避，不当作密钥问题

现场恢复步骤：

1. 先关掉仍在轮询的插件页（否则解封后会立刻被再次封禁）
2. 重启 CPA 可**立即**清除封禁（记录只在进程内存里），或等倒计时结束
3. 回管理中心重新登录并勾选「记住密码」；若用 `cliproxy run --password` 的本地密码，注意它不一定每次启动都相同

## 使用

1. 打开 **Grok 账号巡检**。
2. 输入 CPA Management Key。
3. 选择并发数、是否包含已禁用账号、是否仅巡检已禁用账号。
4. 点击 **开始巡检** 或 **增量巡检**。
5. 根据结果执行 **一键建议操作**、批量禁用、批量删除或单账号操作。

巡检和批量操作都在后台执行。页面关闭或切换后任务仍会继续；重新打开页面可查看当前进度和上次结果。

点 **停止** 会立即结束本轮巡检：尚未探测的账号会标记为「已停止，未探测」。

## 结果说明

| 结果 | 默认建议 | 含义 |
|------|----------|------|
| 健康 | 保留；如果已禁用则建议启用 | 对话探测成功，账号可用 |
| 权限被拒 | 禁用 | 账号没有对话权限、被拒绝或权限受限 |
| 额度用尽 | 禁用 | 免费额度用尽，暂时不适合继续调度 |
| 需重新登录 | 删除 | 登录态失效，删除后需在 CPA 重新登录 |
| 模型不可用 | 保留 | 当前探测模型不可用，不一定代表账号失效 |
| 探测异常 | 保留 | 网络或上游异常，建议复查后再处理 |

**一键建议操作** 只处理建议为禁用、启用、删除的账号。  
**批量禁用 / 批量删除** 会按当前筛选结果强制执行，请确认筛选条件后再操作。

## 数据说明

- 巡检结果会保存在 CPA 工作目录下的 `data/grok-inspection/results.json`
- 结果文件只保存展示所需信息，不保存完整 token
- 实时自动禁用默认开启：命中 free-usage-exhausted / personal-team-blocked:spending-limit / permission-denied / 401 时会自动禁用；可在「实时自动禁用」页关闭。巡检页的建议操作仍需确认后执行
- 删除操作会删除对应 Auth 凭证，恢复需要重新登录

## License

MIT

## 社区

本开源项目与 LINUX DO 社区相关联，并致谢该社区。
