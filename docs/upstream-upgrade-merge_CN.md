# 上游升级合并指南

本文档用于将 `router-for-me/CLIProxyAPI` 上游版本合并到当前定制分支，同时保留 CPA 场景下的本地运行时优化。目标不是仅消除 Git 冲突，而是保证本地功能契约、并发语义和运行路径在上游重构后仍然完整。

## 最近一次合并基线

最近一次已验证合并：

```text
本地基线：1e3488ac473a89ec21732e237d61c25c573650bf
上游版本：v7.2.128
上游提交：bd34ceca04209ef0460f4b05e3a1a047fb7fad2a
合并提交：9aabf19edff6020aa4808fe7bb42bb0ac670f435
合并分支：codex/merge-upstream-v7.2.128
```

该提交必须保持两个父提交：

```bash
git rev-list --parents -n 1 9aabf19e
```

预期父提交顺序：

```text
1e3488ac473a89ec21732e237d61c25c573650bf
bd34ceca04209ef0460f4b05e3a1a047fb7fad2a
```

合并前工作区备份：

```text
/tmp/CLIProxyAPI-Pro-pre-upstream-v7.2.128.patch
SHA256: 9a063eaf2880c60326a27a5a0a839e6e00e1cd25bbdde3b1014fdb7068832d70
```

临时目录备份只用于本机应急。长期保留应使用 Git 分支、标签或 bundle。

本次合并过程中曾出现、最终必须纳入版本控制的本地新增文件：

```text
internal/api/handlers/management/auth_files_import.go
internal/runtime/executor/codex_websockets_agent_identity_test.go
internal/runtime/executor/codex_websockets_pool.go
sdk/cliproxy/auth/session_affinity_response.go
sdk/cliproxy/auth/session_affinity_response_execution_test.go
sdk/cliproxy/service_auth_runtime.go
```

以后处理拆文件冲突时，`git ls-files --others --exclude-standard` 与 `git status` 两项检查缺一不可。

## 本地能力清单

后续合并必须逐项确认以下能力，不应以“代码仍存在”代替“执行路径仍调用”。

### 1. Agent Identity

功能范围：

- Agent Identity bundle 解析、导入和稳定命名。
- 异步任务注册、单飞控制、退避重试和手动重建。
- runtime deleted、task rejected 等终态识别。
- 恢复状态、历史记录和管理接口。
- 凭据变更时 fail closed，避免旧任务与新密钥混用。
- Authorization 完整值透传，支持 `AgentAssertion ...`。
- Agent Identity 不进入普通 OAuth token 自动刷新。

主要文件：

```text
internal/auth/codex/agent_identity.go
internal/auth/codex/agent_identity_bundle.go
internal/auth/codex/agent_identity_registration.go
internal/auth/codex/agent_identity_recovery.go
internal/api/handlers/management/auth_files_agent_identity_registration.go
internal/api/handlers/management/auth_files_import.go
internal/watcher/synthesizer/agent_identity.go
sdk/cliproxy/auth/conductor_refresh.go
```

高风险点：

- 上游拆分 `auth_files.go` 时，导入逻辑可能变成未跟踪的新文件，容易漏进提交。
- 判断 Agent Identity 必须同时覆盖已挂载 runtime 和仅存在 metadata 的阶段。
- WebSocket、普通 HTTP、管理 API Call 必须使用完整 Authorization 值；仅对旧格式裸 token 添加 `Bearer `。
- watcher 重建 `Auth` 时必须保留 Agent Identity runtime、注册状态和凭据版本语义。

### 2. Runtime Limits 和终态隔离

功能范围：

- 每凭据并发槽、请求窗口和选择冻结。
- Sticky bypass 和 Tail Burst 例外路径。
- 401 或终态凭据立即退出可选池。
- 普通执行、流式执行、CountTokens 和 Home 执行使用一致的容量控制。
- 所有成功、失败、重试、取消和提前返回路径都释放 runtime slot。

主要文件：

```text
sdk/cliproxy/auth/runtime_limits.go
sdk/cliproxy/auth/types.go
sdk/cliproxy/auth/conductor_execution.go
sdk/cliproxy/auth/conductor_stream.go
sdk/cliproxy/auth/conductor_home_execution.go
sdk/cliproxy/auth/conductor_lifecycle.go
sdk/cliproxy/service_auth_runtime.go
```

高风险点：

- `ExecuteCount` 很容易在上游重构时绕过 runtime slot。
- 获取 slot 后，正常返回、重试、错误和取消分支都要审计释放动作。
- `Auth` 会被浅复制。不要直接把 `sync.Mutex`、`sync.Once` 或 `atomic.Pointer` 作为可复制状态加入 `Auth`。
- 当前 `runtimeLimits` 保持普通指针字段，并通过 `unsafe.Pointer` 与 `sync/atomic` CAS 做并发安全的懒初始化。
- `Auth.Clone()` 必须先初始化共享状态，再执行浅复制；watcher 更新时也要复用已有状态。

### 3. 响应 ID 会话粘性

Codex Responses 返回的 `response.id` 和 `previous_response_id` 会参与后续请求路由。合并后必须保证响应 ID 与实际执行凭据绑定。

主要文件：

```text
sdk/cliproxy/auth/session_affinity_response.go
sdk/cliproxy/auth/conductor_execution.go
sdk/cliproxy/auth/conductor_stream.go
sdk/cliproxy/auth/conductor_home_execution.go
sdk/cliproxy/auth/session_affinity_response_execution_test.go
```

必须覆盖的路径：

- 普通 `Execute`。
- `ExecuteCount`。
- 流式响应完成后的最终 payload。
- Home dispatcher 返回结果。

流式路径需要区分：

```text
affinityModel：用于会话绑定的路由模型
resultModel：最终结果和错误处理使用的模型
```

上游变量改名或抽取函数后，二者仍需保持独立语义。

### 4. Codex WebSocket 池和断流恢复

功能范围：

- stateless WebSocket 并行池。
- 最大 30 个槽，预热 3 个 standby 连接。
- HTTP SSE 复用 WebSocket。
- 上游断流后恢复。
- 空完成输出回填。
- 终态 Agent Identity 任务处理。
- 服务停止或配置切换时清理 stateless 会话池。

主要文件：

```text
internal/runtime/executor/codex_websockets_pool.go
internal/runtime/executor/codex_websockets_connection.go
internal/runtime/executor/codex_websockets_execute.go
internal/runtime/executor/codex_websockets_stream.go
internal/runtime/executor/codex_websockets_session.go
internal/runtime/executor/codex_websockets_executor.go
```

Authorization 必须通过统一函数设置：

```text
setCodexAuthorizationHeader
applyCodexWebsocketHeaders
```

必须测试三种输入：

```text
Bearer TOKEN
AgentAssertion ASSERTION
旧格式裸 token
```

禁止无条件执行 `"Bearer " + token`，否则会产生：

```text
Bearer Bearer TOKEN
Bearer AgentAssertion ASSERTION
```

### 5. Tail Burst 和 Quota Collector

主要文件：

```text
sdk/cliproxy/auth/codex_tail_burst.go
internal/runtime/executor/codex_tail_burst_quota_collector.go
internal/api/handlers/management/codex_tail_burst.go
sdk/cliproxy/service_auth.go
internal/config/config_types.go
```

合并时要同时检查：配置解析、默认值、管理路由、collector 生命周期、selector 以及 runtime limit 的 Tail Burst 旁路。只保留配置字段而漏掉 collector 启动或 selector 调用，会形成静默失效。

### 6. 每凭据 Source IP 出口

功能范围：

- 普通 HTTP transport。
- uTLS transport。
- Codex WebSocket dialer。
- OAuth refresh 和设备授权客户端。
- 管理 API Call。
- transport 缓存键包含 proxy URL 与 source IP。

主要文件：

```text
sdk/proxyutil/proxy.go
sdk/cliproxy/rtprovider.go
internal/runtime/executor/helps/proxy_helpers.go
internal/runtime/executor/helps/utls_client.go
internal/runtime/executor/codex_websockets_connection.go
internal/auth/codex/openai_auth.go
internal/auth/claude/anthropic_auth.go
internal/auth/claude/utls_transport.go
internal/api/handlers/management/api_tools.go
```

出口优先级保持为：

```text
auth.proxy_url
auth.source_ip（配置后绕过全局代理）
全局 proxy_url / source_ip
```

池键和 transport 缓存键必须包含 source IP，避免不同出口复用同一个连接。

## 本次合并发现的问题

### 问题 1：函数仍存在，但调用点被上游重构删除

上游把 conductor、service、Codex executor 和 WebSocket executor 拆成多个文件。Git 冲突解决后，本地辅助函数仍能编译，但调用点可能已经消失。

本次发现响应 ID 粘性函数仍存在，但普通执行、CountTokens、流式和 Home 路径的调用部分丢失。仅检查冲突标记或编译会漏掉此类问题。

后续必须执行“本地新增函数引用审计”：

```bash
UPSTREAM_TAG=vX.Y.Z
git diff --function-context "$UPSTREAM_TAG"..HEAD -- sdk/cliproxy/auth
rg -n "bindSessionAffinityFromResponsePayload" sdk/cliproxy/auth
rg -n "acquireRuntimeSlot|releaseRuntimeSlot" sdk/cliproxy/auth
rg -n "setCodexAuthorizationHeader|applyCodexWebsocketHeaders" internal/runtime/executor
```

对关键函数比较合并前后的引用数量，而不只是确认定义存在。

### 问题 2：CountTokens 绕过容量控制

上游执行路径拆分后，`ExecuteCount` 没有继承普通执行的 runtime slot 获取和 Sticky bypass 上下文。本次已恢复，并补充并发槽测试。

后续新增任何执行入口时，都要检查：

```text
选择凭据 -> 获取 runtime slot -> 调用 executor -> 记录结果 -> 释放 slot
```

### 问题 3：Agent Identity 误入 OAuth 自动刷新

仅检查 runtime 类型不足以覆盖 watcher 尚未挂载 runtime 的阶段。`shouldRefresh` 必须先从 metadata 识别 Agent Identity，否则会把它当作普通 OAuth 凭据刷新。

对应回归测试：

```text
sdk/cliproxy/auth/conductor_agent_identity_refresh_test.go
```

### 问题 4：WebSocket Authorization 重复添加 Bearer

上游拆分 WebSocket header 构建后，把 Authorization 当成裸 token。本地 Agent Identity 返回的是完整 header 值，因此产生重复前缀。本次统一使用 `setCodexAuthorizationHeader`。

对应回归测试：

```text
internal/runtime/executor/codex_websockets_agent_identity_test.go
```

### 问题 5：Runtime limits 懒初始化存在竞争

并发请求可能同时初始化 `Auth.runtimeLimits`。最初使用全局锁虽能保证正确性，但会扩大热路径锁竞争。最终采用原子 CAS 初始化，并保持 `Auth` 可浅复制。

对应验证：

```bash
go test -race ./sdk/cliproxy/auth
```

### 问题 6：测试辅助对象自身存在竞争

本地并发测试中的 `started` channel 指针曾被多个 goroutine 读写。测试已改为通过 `sync.Once` 关闭固定 channel。后续 race 报告要先区分产品代码与测试夹具竞争。

## 标准合并流程

建议在同一个 shell session 中执行，并先设置：

```bash
UPSTREAM_TAG=vX.Y.Z
VERSION="$UPSTREAM_TAG"
LOCAL_BASELINE=$(git rev-parse HEAD)
```

### 1. 更新远端并记录引用

```bash
git fetch upstream --tags --prune
git status --short
printf 'local baseline: '; git rev-parse "$LOCAL_BASELINE"
git rev-parse "$UPSTREAM_TAG"
git log --oneline --decorate HEAD.."$UPSTREAM_TAG"
```

工作区应先保持干净。存在用户改动时，先创建独立提交或完整备份，不要在合并过程中覆盖。

### 2. 创建分支与可恢复备份

```bash
git switch -c "codex/merge-upstream-$VERSION"
git bundle create "/tmp/CLIProxyAPI-Pro-before-$VERSION.bundle" --all
git diff --binary > "/tmp/CLIProxyAPI-Pro-before-$VERSION-worktree.patch"
```

记录校验值：

```bash
LC_ALL=C shasum -a 256 "/tmp/CLIProxyAPI-Pro-before-$VERSION.bundle"
LC_ALL=C shasum -a 256 "/tmp/CLIProxyAPI-Pro-before-$VERSION-worktree.patch"
```

### 3. 以 no-commit 模式合并

```bash
git merge --no-commit --no-ff "$UPSTREAM_TAG"
git diff --name-only --diff-filter=U
```

不要对大文件或整个目录直接选择 `ours` 或 `theirs`。应按功能契约逐段合并，尤其关注：

```text
internal/api/handlers/management/
internal/config/
internal/runtime/executor/
internal/watcher/
sdk/cliproxy/auth/
sdk/cliproxy/service.go
sdk/cliproxy/service_auth.go
sdk/cliproxy/service_auth_runtime.go
sdk/cliproxy/service_config.go
sdk/cliproxy/service_lifecycle.go
```

### 4. 按子系统解决并立即测试

推荐顺序：

1. config 类型、默认值、加载和 normalization。
2. Auth 类型、Clone、watcher 和 service 生命周期。
3. management 路由、导入与管理接口。
4. conductor 选择、执行、刷新和 runtime limits。
5. Codex HTTP、WebSocket、Agent Identity 和 Tail Burst。
6. Source IP 与 transport 缓存。

每完成一个子系统，先运行对应包测试，缩小问题定位范围。

### 5. 做静默回归审计

```bash
grep -RIn --exclude-dir=.git -E '^(<<<<<<<|=======|>>>>>>>)' .
git diff --name-only --diff-filter=U
git ls-files --others --exclude-standard
git diff --check
```

比较上游与最终结果中的本地能力：

```bash
LOCAL_BASELINE=$(git rev-parse ORIG_HEAD)
git diff --stat "$UPSTREAM_TAG"
git diff --name-only "$UPSTREAM_TAG"
git log --reverse --oneline "$UPSTREAM_TAG".."$LOCAL_BASELINE"
```

重点查找：

- 本地新增文件是否变成未跟踪文件。
- 本地函数是否只有定义没有调用。
- 上游文件拆分后，配置字段是否缺少默认值、加载、热更新或路由。
- 获取资源后是否覆盖所有释放路径。
- 完整 Authorization 值是否被当成裸 token。
- transport、连接池和 session pool 的 key 是否遗漏新维度。

### 6. 完整验证

标准验证命令：

```bash
go test ./sdk/cliproxy/auth
go test ./internal/runtime/executor
go test ./...
go build -o /tmp/cli-proxy-api-merged ./cmd/server
go vet ./sdk/cliproxy/auth
git diff --check
```

独立 example module 也要测试：

```bash
(cd examples/plugin/request-lifecycle/go && go test ./...)
(cd examples/realtime-openai-go && go test ./...)
```

竞态测试：

```bash
go test -race ./sdk/cliproxy/auth
go test -race ./internal/runtime/executor \
  -run 'Test(ApplyCodexWebsocketHeadersPreservesCompleteAuthorization|CodexWebsocketHandshakeRecoversRejectedAgentIdentityTask|CodexStatelessWebsocketSessionPool.*|CodexWebsockets.*)$'
```

本次合并增加或强化的关键测试：

```text
sdk/cliproxy/auth/session_affinity_response_execution_test.go
sdk/cliproxy/auth/conductor_agent_identity_refresh_test.go
sdk/cliproxy/auth/runtime_limits_test.go
internal/runtime/executor/codex_websockets_agent_identity_test.go
internal/runtime/executor/codex_websocket_session_pool_test.go
```

### 7. 暂存与提交前检查

```bash
git add -A
git diff --cached --check
git diff --cached --stat
git diff --cached --name-status
git diff --name-only --diff-filter=U
git ls-files --others --exclude-standard
```

确认无未暂存内容：

```bash
git diff --quiet
```

创建 merge commit 后验证双父关系：

```bash
git commit -m "merge: integrate upstream $VERSION with local runtime optimizations"
git show --no-patch --format='commit=%H%nparents=%P%nsubject=%s' HEAD
git merge-base --is-ancestor "$LOCAL_BASELINE" HEAD
git merge-base --is-ancestor "$UPSTREAM_TAG" HEAD
git status --short
```

## 已知上游测试噪声

每次升级都要重新与对应上游版本比较，确认问题确实来自上游未修改文件；已知噪声结论仅适用于当次目标版本。

### Antigravity credits race

本次全量命令：

```bash
go test -race ./sdk/cliproxy/auth ./internal/runtime/executor
```

`sdk/cliproxy/auth` 通过；`internal/runtime/executor` 报告 Antigravity credits 异步测试清理竞争，位置：

```text
internal/runtime/executor/antigravity_executor_credits_test.go
resetAntigravityCreditsRetryState()
```

该文件与 `v7.2.128` 上游一致。Codex/WebSocket 定向 race 测试通过。

### 全量 go vet

`go vet ./...` 在以下上游文件存在既有问题：

```text
internal/logging/request_logger_body_source.go
internal/pluginhost/host_callbacks.go
internal/pluginhost/host_model_stream_callbacks.go
```

分类为上游问题前必须验证文件未被本地修改：

```bash
git diff --exit-code "$UPSTREAM_TAG" -- \
  internal/logging/request_logger_body_source.go \
  internal/pluginhost/host_callbacks.go \
  internal/pluginhost/host_model_stream_callbacks.go
```

本地核心包仍应单独通过：

```bash
go vet ./sdk/cliproxy/auth
```

## 合并完成判定

以下条件全部满足后，才视为升级合并完成：

- Git 无冲突标记、无 unmerged 文件、无意外未跟踪文件。
- 合并提交同时包含本地基线和目标上游提交。
- 本地能力清单逐项确认存在实际调用路径。
- 全量标准测试和 server build 通过。
- 核心 auth race 测试及 Codex/WebSocket 定向 race 测试通过。
- 已知上游测试噪声经过当前目标版本重新比对。
- merge commit 后工作区干净。
- 发布前另行执行部署检查，不把“合并通过”等同于“可直接重启生产服务”。
