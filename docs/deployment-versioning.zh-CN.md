# CPA Core 日期时间版本号标准

Core 生产构建统一使用提交日期与时间作为版本号：

```text
YYYYMMDD-HHMMSS
```

- 默认时区：`Asia/Shanghai`。
- 时间来源：构建所用 Git commit 的提交时间。
- 示例：`20260816-143205`。
- 同一提交重复构建时版本号保持一致。
- 生产镜像仍必须同时注入完整 `COMMIT` 与 UTC `BUILD_DATE`，用于精确追踪源码和实际构建时间。

生成命令：

```bash
VERSION="$(./scripts/compact-version.sh)"
COMMIT="$(git rev-parse HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

如需在其他时区生成版本号，可显式设置：

```bash
CPA_VERSION_TIMEZONE=UTC ./scripts/compact-version.sh
```

生产发布默认保持 `Asia/Shanghai`，Core、Manager、Agent 均遵循相同格式。
