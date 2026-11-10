# VPS 节点上线（vps-node skill）

把「新买的 VPS → 可用节点」这套流程固化成可复用的自动化脚本包，**先验货，再装机**。

适用 WorkBuddy / Claude Code 类支持 skill 的 Agent 环境；也可以完全脱离 Agent，直接跑 `scripts/` 下的脚本。

## 它解决什么问题

手工搭一个节点，通常是：SSH 上去 → 装 sing-box → 手写配置 → 搞证书 → 加固 → 出问题再回来查。中间任何一步错，都是在已经付了钱、机器已经上线的状态下返工。

这套流程把顺序纠正为：

```
① 验货（只读，不装任何东西）→ 不满意就退款，零成本退出
② 部署（sing-box 双协议 + BBR + 免费域名 HTTPS 订阅）
③ 人工确认 3 件事（客户端激活 / 补丁重启 / 真机试连）
④ 验收（只查配置对不对）
⑤ 装哨兵（服务端采集 + 每日自动体检）
```

## 能力清单

| 能力 | 脚本 |
|---|---|
| 验货：硬件 / 虚拟化 / 磁盘写速 / 出网 / IP 类型 / 回程 AS / AI 站可达 | `vps-precheck.sh` |
| 九源 IP 信誉体检（Fraud Score、DNSBL、AbuseIPDB、代理/机房判定） | `vps-external-ip-check.sh` |
| 部署：sing-box（VLESS+REALITY :443 + Hysteria2 :8443）+ BBR | `vps-node-init.sh` |
| DuckDNS + Let's Encrypt DNS-01 + HTTPS 订阅端点（:2096） | 同上 |
| 安全加固：ufw / sshd / sysctl / fail2ban / 补丁 | `vps-harden.sh` |
| 全流程编排（6 步，含凭据落盘与密钥安装） | `bootstrap-new-vps.sh` |
| 验收：443 / REALITY 借壳证书 / 订阅 / 延迟 / 出口 IP | `vps-verify.sh` |
| 去程 + 回程路由分析（traceroute + nexttrace） | `vps-route-check.sh` |
| 深度质量报告（NodeQuality 封装，跑完自动归档） | `vps-quality-report.sh` |
| 两次快照对比（硬件 / IP 风险 / 解锁 / 三网延迟） | `vps-quality-parse.py` `vps-quality-diff.*` |
| 哨兵：即时体检 | `vps-sentinel.sh` |
| 哨兵：服务端 cron 采集 + 本机拉取分析 | `vps-sentinel-agent.sh` `vps-sentinel-fetch.sh` `vps-sentinel-install.sh` |
| 生成日检 / 周检 automation 规格 | `vps-automation-spec.sh` |

## 安装

```bash
git clone https://github.com/<you>/vps-node-skill.git ~/.workbuddy/skills/vps-node
chmod +x ~/.workbuddy/skills/vps-node/scripts/*.sh
```

Agent 环境会在启动时扫描 skill 目录；之后用自然语言说「我买了个新 VPS，IP x.x.x.x，帮我看看值不值」即可自动触发。

## 快速开始

```bash
cd ~/.workbuddy/skills/vps-node

# 1. 验货（只读，1-5 分钟）
bash scripts/vps-precheck.sh <IP> <SSH端口> '<root密码>' --ipaudit

# 2. 部署（需要先有 DuckDNS 子域名与 token）
bash scripts/bootstrap-new-vps.sh <IP> <SSH端口> '<root密码>' <duckdns子域名> <duckdns_token>

# 3. 验收
bash scripts/vps-verify.sh <凭据别名>

# 4. 装哨兵（服务端每 10 分钟采集）
bash scripts/vps-sentinel-install.sh <凭据别名> --home-ip <你家宽出口IP>

# 5. 生成日检 + 周检 automation 规格
bash scripts/vps-automation-spec.sh <凭据别名> --json
```

凭据统一落在 `~/.vps-node/<别名>.json`（权限 600），后续所有脚本都从这里读参数——**换机器只需换这个文件**。

## 设计要点

- **验货在设计上只读**：`vps-precheck.sh` 不写远端文件、不装软件，退出码 `0`（合格）/ `1`（有警告）/ `2`（不合格）
- **不碰节点结构做增值改造**：挂住宅上游、加第二出口都只改 `outbounds` / `route`，443 / REALITY / 订阅一律不动，回滚是还原一个备份文件
- **哨兵是双层**：VPS 侧 cron 每 10 分钟写一条 JSONL（Mac 关机不影响采集），Mac 侧开机拉取 + 本机复测 + 异常聚合
- **UDP 单独处理**：多数住宅代理只代理 TCP，SOCKS5 UDP ASSOCIATE 会被拒，所以固定加一条 `{"network":"udp","outbound":"direct"}` 规则排在路由最前

## 已知限制

- NodeQuality 的「国内测速」在境外 VPS 上必然全红：Ookla 对境外 IP 隐藏国内测速节点，与机器质量无关
- NodeQuality 结果会上传第三方并生成**公开且不可撤回**的链接；介意就只用 `vps-external-ip-check.sh` + `vps-route-check.sh`
- 脚本按 macOS 自带 bash 3.2 验证过（`/bin/bash -n` 全过），Linux 上同样可用
- 需要 `expect`（密码登录模式）、`nexttrace`（回程 AS 判定，缺失时回落 mtr）

## 许可

MIT，见 [LICENSE](LICENSE)。脚本涉及服务器 root 操作，请先在自己的机器上读懂再执行。
