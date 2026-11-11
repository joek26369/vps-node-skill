---
name: vps-node
description: Pre-flight a freshly bought VPS (hardware / IP reputation / return route, nothing installed) and only then provision a production-ready proxy node — sing-box (VLESS+REALITY :443 + Hysteria2 :8443), BBR tuning, DuckDNS + Let's Encrypt HTTPS subscription endpoint, security hardening (ufw/SSH/sysctl/fail2ban), and a 9-source external IP reputation audit. Use when the user buys a new VPS, wants to set up a 节点/机场/梯子, replace a residential proxy node, or asks to harden + audit a VPS.
description_zh: "新 VPS 上线全流程：先验货（硬件/IP 质量/回程，不装机）→ sing-box 双协议节点 + BBR + 免费域名 HTTPS 订阅 + 安全加固 + IP 风险体检 → 验收 → 服务端哨兵"
description_en: "One-shot VPS node deployment: sing-box dual protocol, BBR, HTTPS subscription via DuckDNS+LE, hardening, IP reputation audit"
version: 1.10.0
allowed-tools: Read,Write,Edit,Bash
display_name: "VPS 节点上线"
visibility: "private"
---

# VPS 节点上线

把一台全新的 Linux VPS 变成可用的代理节点。**分两段：先验货，决定留下再装机。**

- 验货（第一步）：1-5 分钟，只读，不装节点软件 —— 不合格就换 IP / 退款，及时止损
- 部署（第三到六步）：6-12 分钟 —— 装机、加固、验收、装哨兵、建两条 automation

## 何时使用

- 用户刚买了 VPS，想先知道**这机器和这个 IP 值不值得留**（只验货，不装机）
- 用户买了新 VPS，要「搭节点 / 配梯子 / 做机场」
- 要替换旧的住宅 IP 节点
- 要对一台已在跑的 VPS 做安全加固或 IP 纯净度体检（可单独跑子脚本）
- 要给已上线的节点建日常监控（哨兵：日检看此刻有没有坏，周检看质量趋势；静默失效主动报警）

**不适用**：Windows VPS、需要面板（3x-ui / x-ui）的场景、纯 CDN 中转方案。

## 第一步：验货（先决定要不要留，再谈装机）

**顺序不能倒。** 先把机器和 IP 查清楚，再决定装什么。装完才发现 IP 被墙、磁盘不够、是 OpenVZ 容器，等于白干一遍，还得拆。

只需要 3 个参数：

| 参数 | 说明 |
|---|---|
| `IP` | VPS 公网 IPv4 |
| `SSH_PORT` | SSH 端口，如 22 / 2222 |
| `ROOT_PASS` | root 初始密码（或 `--key <私钥路径>`） |

```bash
bash scripts/vps-precheck.sh <IP> <SSH_PORT> '<ROOT_PASS>'
bash scripts/vps-precheck.sh <IP> <SSH_PORT> --key ~/.ssh/id_ed25519_xxx
TARGET=<家宽出口IP> bash scripts/vps-precheck.sh <IP> <SSH_PORT> '<ROOT_PASS>'   # 回程打到自己家，看真实落地
```

只读，不改节点配置。唯一装上去的是 `nexttrace`（看回程 AS 路径必需，装不上退 mtr 并说明）。

### 三档深度，按需选

| 档 | 加什么参数 | 总耗时 | 多查的内容 |
|---|---|---|---|
| 快检（默认） | — | 1-3 分钟 | 机器 / IP 基础情报 / 回程 AS / **AI 站连通性** |
| + IP 风险体检 | `--ipaudit` | +1-2 分钟 | 9 项：ipinfo 匿名化六项、Scamalytics Fraud Score、AbuseIPDB 举报、DNSBL 黑名单 |
| + 硬件全景 | `--deep`（需密钥） | +10-20 分钟 | NodeQuality：Yabs 跑分、流媒体解锁、三网测速（2-3GB 流量，报告公开） |

`--all` 等于快检 + 两项。**部署编排器默认跑前两档**，`SKIP_IPAUDIT=1` 可关掉第二档。

> 为什么这三项必须在装机前：它们查的是「机器本体 + IP 本身」，装不装节点结果完全一样。装完再查，发现问题只能拆掉重来。

### 查什么

| 维度 | 项 | 判据 |
|---|---|---|
| 机器 | 磁盘可用 | **< 2 GB 否决**（装不下 sing-box + 证书 + 日志）；< 5 GB 警告 |
| | 内存 | **< 256 MB 否决**；< 512 MB 警告 |
| | 虚拟化 | **OpenVZ / LXC 否决** —— 内核参数不可改，BBR 与 sysctl 加固全部失效 |
| | 出网 | **github 不通否决**（装不了 sing-box） |
| | 磁盘写速 | < 50 MB/s 警告，可能严重超售 |
| | 下行实测 | < 20 Mbps 警告，与标称带宽差距大 |
| | 443 占用 | 已被占用则警告（REALITY 需要 443） |
| | 已装 sing-box / xray / 3x-ui | 警告，重装会覆盖现有配置 |
| IP | 归属 / ASN / 运营商 | 决定线路质量与 AI 站风控倾向 |
| | proxycheck risk | ≥ 40/100 警告 |
| | ip-api proxy 标记 | 被标为代理出口，Claude / ChatGPT 更容易触发人机验证 |
| | 出口 IP vs 购买 IP | **不一致就是问题** —— 上游 NAT 或 IP 被换，立刻问商家 |
| 回程 | AS 路径 | 出现 AS9929 / AS4809 / AS10099·AS58807(CUG) = 精品段；全程 AS4837 属常规；纯 AS4134 且丢包高要留意 |
| AI 站 | claude.ai / chatgpt.com / api.anthropic.com | 从 VPS 本机直连。**只判网络层能不能通**；403 + cf-mitigated 是机房 IP 裸 curl 的常态，不参与裁决 |

### 三种结论

| 退出码 | 含义 | 怎么做 |
|---|---|---|
| `0` | ✅ 通过 | 进第二步 |
| `1` | ⚠️ 有警告 | 可部署，但要清楚自己在接受什么 |
| `2` | ❌ 否决 | **别装。** 拿报告开工单：换 IP / 换节点 / 退款 |

典型否决案例：OpenVZ 容器（BBR 开不了）、磁盘只剩 1.5 GB、IP 风险分 80、出口 IP 与购买 IP 不符。

> 预检 ≠ 第五步的验收。预检查「这台机器值不值得要」，验收查「节点配好没有」。前者在装之前，后者在装之后。

## 第二步：决定留下后，补齐 DuckDNS 参数

验货通过再折腾域名。这步要 2 个参数（另可选 `DEST`）：

| 参数 | 说明 | 必填 |
|---|---|---|
| `DUCKDNS_SUB` | DuckDNS 子域名前缀，如 `your-node`（**不要**带 `.duckdns.org`） | ✅ |
| `DUCKDNS_TOKEN` | DuckDNS 账户 token | ✅ |
| `DEST` | REALITY 借壳站点，默认 `www.paypal.com` | 可选 |

### DuckDNS token 怎么拿（用户若没有，给出这段）

1. 打开 https://www.duckdns.org ，用 GitHub / Google 登录
2. 顶部 **token** 就是所需值
3. 在 **domains** 输入框填入子域名前缀并点 `add domain` —— **这步必须做，脚本只能更新记录不能创建域名**

### DEST 选站原则

必须是：支持 TLS 1.3 + HTTP/2、海外大站、**不要** Cloudflare 免费版（TLS 指纹特征明显）、不要和 VPS 同网段。可用：`www.paypal.com`、`www.bing.com`、`www.apple.com`、`swdist.apple.com`、`www.lovelive-anime.jp`。换站直接改第 6 个参数。

## 第三步：执行部署

```bash
bash ~/.workbuddy/skills/vps-node/scripts/bootstrap-new-vps.sh \
  <IP> <SSH_PORT> '<ROOT_PASS>' <DUCKDNS_SUB> <DUCKDNS_TOKEN> [DEST]
```

可选环境变量（前置）：

```bash
# 把家宽出口 IP 加进 fail2ban 白名单（避免自己误封）
WHITELIST_IP=192.0.2.10 bash bootstrap-new-vps.sh ...

# 跳过系统补丁升级（快约 2 分钟，但会留待装补丁）
HARDEN_UPGRADE=0 bash bootstrap-new-vps.sh ...

# 跳过预检里的 9 项 IP 体检（快 1-2 分钟，但不建议）
SKIP_IPAUDIT=1 bash bootstrap-new-vps.sh ...
```

> 服务端哨兵**不在编排器里**——它要等验收全绿之后才能装（见第六步）。给坏节点装上监控，只会让监控持续报错。

### 编排器做什么（6 步）

| 步 | 动作 | 失败即停 |
|---|---|---|
| 1 | **验货**（`vps-precheck.sh --ipaudit`）：机器 / IP 质量 9 项 / 回程 / AI 站连通，判 FAIL 则中止 | 是（`FORCE=1` 可强推） |
| 2 | 上传并执行 `vps-node-init.sh`（8 子步，2-4 分钟） | 是 |
| 3 | 解析 `VPS_RESULT_JSON`，凭据落 `~/.vps-node/<sub>.json`（600） | 是 |
| 4 | 装 ed25519 公钥、关密码登录，**验证密钥可登录后才继续** | 是 |
| 5 | 上传并执行 `vps-harden.sh`（ufw/SSH/sysctl/fail2ban/补丁） | 部分容忍 |
| 6 | `clash://` 深链导入 Verge 新档案 | 否 |

第 2 步内部：依赖 → BBR → sing-box 最新版 → 生成凭据 → REALITY+Hy2 配置 → Clash YAML → DuckDNS+LE 证书+HTTPS 订阅(:2096) → 自检。

## 第四步：必须人工确认的 3 件事

这三项**无法自动化**，跑完要明确告知用户：

1. **Verge 卡片激活** —— 深链只是把订阅塞进 Verge，必须让用户去「配置」页点一下 `xxx-VPS` 卡片才会真正生效（Verge 的热重载被路径白名单挡住）
2. **重启（如果提示）** —— 有内核/系统补丁更新时，脚本只打印提示，需用户执行 `ssh -p <PORT> root@<IP> 'systemctl reboot'`
3. **国内 TCP 视角** —— 打开 `https://tcp.ping.pe/<IP>:443` 看 CN 行，页面是 JS 渲染抓不到

## 第五步：验收（只查「节点配好没有」，必须全绿才进下一步）

机器本体、IP 质量、AI 站可达性在第一步已经查过，**装完节点也不会变**，所以这里不再重复。验收只查一件事：配置对不对。

| 项 | 工具 | 判什么 |
|---|---|---|
| 端口 / REALITY | `vps-verify.sh` | 443 可连；REALITY 握手拿回 dest 站点的真证书（非自签） |
| 订阅 | `vps-verify.sh` | HTTPS 200、含 `proxies:`、证书余期够 |
| 延迟 / 出口 | `vps-verify.sh` | REALITY 与 Hy2 < 400ms；出口 IP 与 VPS 一致 |
| 真浏览器 | `vps-verify.sh --browser` | headless 只做初筛；**最终请你自己在浏览器打开 claude.ai 确认** —— headless 指纹与真浏览器不同，它过不代表你能过 |
| 完整线路 | `vps-route-check.sh` | 去程 + 回程 ASN 全标注，比第一步的简化回程更细（含本机到 VPS 的去程） |

```bash
# 节点验收（443 可达 / REALITY 借壳证书 / 订阅有效性 / 延迟 / 出口 IP / headless 浏览器直连）
bash scripts/vps-verify.sh <IP> --browser

# 线路体检（去程 traceroute + 回程 nexttrace；第 3 参数传家宽出口 IP 复核送中与真实落地路径）
bash scripts/vps-route-check.sh <IP> <SSH_PORT> <家宽出口IP>
```

`vps-verify.sh` 会自动从 `~/.vps-node/<sub>.json` 读 IP / 域名 / 订阅 URL / dest。

### 验收通过标准

- TCP 443 可连接
- REALITY 握手返回 dest 站点真实证书（不是自签）
- HTTPS 订阅 HTTP 200 且含 `proxies:`
- REALITY 延迟 < 400ms（正常 150-250ms）
- 出口 IP 与 VPS 一致
- claude.ai / chatgpt.com 出现登录或对话界面，无 CF 挑战
- 回程路径出现 AS9929 / AS4809 / AS10099·AS58807（CUG）视为优质；全程 AS4837 属常规；纯 AS4134 且丢包高需留意

（IP 纯净度、Fraud Score、Anonymization 六项已在第一步验过，不在这里重复判断。）

以上全部满足才算验收通过，之后才进第六步装哨兵。有任何一条不满足，先修，别装。

## 第六步：装哨兵（验收通过之后，含两条 automation）

**前置条件：第五步验收全绿。** 443 打不通、REALITY 证书是自签、订阅 404 这类问题要先修好，再装哨兵——否则哨兵从第一天起就报红，后面的观察期数据也全是噪声。

顺序固定为：验货 → 部署 → 激活 → 验收 → **装采集器** → **建 automation（日检 + 周检）**。

### 为什么要建哨兵

代理节点是**「静默失效」型服务**：它不会像网站那样返回 500，只会让你「突然连不上 / 突然变慢 / 突然开始被风控」。部署验收只是开机自检，开机之后没人盯着，故障就只能靠你自己撞上。建哨兵的本质是把「被动踩坑」换成「主动报警」——具体是盯住六种不会自己喊出来的事：

| 会静默发生的事 | 不建哨兵你会怎么发现 | 哨兵怎么提前发现 |
|---|---|---|
| sing-box 挂了 / 重启后没起来 | 下次上网连不上 | 每天查 `systemctl is-active` + 443 监听 → 退出码 2 |
| IP 被送中 / 路由横跳，延迟 180ms → 800ms | 只觉得「今天有点卡」，说不出哪天开始的 | 每天记 REALITY / Hy2 延迟，>400ms 判警告 |
| 出口 IP 被上游悄悄换掉（住宅 IP 的全部溢价都押在这上面） | 等 claude.ai / ChatGPT 开始风控才警觉 | 每天比对出口 IP，一变立刻报严重 |
| Let's Encrypt 证书没续上（DNS 变了 / LE 限流 / cron 被清） | 90 天后某天半夜订阅链接突然打不开 | 读证书余期，<14 天报警告 |
| IP 信誉被同段滥用拖脏 | 无缘无故被 CF 拦、被人机验证，找不到原因 | 周日 `--risk` 跑 Fraud Score / proxycheck |
| 磁盘被日志 / 缓存慢慢吃满（20G 装完剩 13G） | 某天 sing-box 写不进配置或证书签发失败 | 周检比磁盘占用，涨 ≥10% 就报 |

除了「救火」，它还有三层是给**决策**用的：

1. **观察期要有数据，不能靠感觉** —— 判断「这台新节点能不能替代旧的住宅节点」，靠的是连续 7-30 天的延迟 / 可用率 / 出口稳定性曲线，而不是买之前那几张测试报告图，也不是某一次测出的 34Mbps。哨兵就是这条曲线的采集器，观察期结束时拿它说话。
2. **降低对人肉的依赖** —— 你不需要每天来问「节点还好吗」。正常只回一行，异常才展开，而且异常已经带分层结论（警告 / 严重）和具体故障项，省掉「先查哪里」的那一轮。
3. **续费 / 退役的判据** —— 499 元年付值不值、旧住宅节点什么时候停，都该看真实可用率与质量趋势（日检给可用率，周检给风险分/解锁/回程漂移的走向），而不是印象。

### 哨兵不是什么（边界说清楚，避免误用）

- **不是站外可用性监控**：探测从本机（Mac）发起，你自己关机 / 断网就测不了。要外部视角得另接 UptimeRobot 这类服务。
- **不做自动修复**：不重启服务、不切节点、不换 IP。只读、只报，这是它能每天裸跑而不出事的前提。
- **不替代部署验收**：`vps-verify.sh` 是一次性深度验收（30 秒跑完，查全套），哨兵是每日浅体检（20 秒，查关键几项）+ 每周质量快照（8-15 分钟，查趋势），互补不重叠。
- **日检成本可忽略**：每天几次 SSH + 延迟探测，不写远端、不占 VPS 资源、几乎不留日志。周检另算：每周一次 NodeQuality 快照，300MB-1GB 流量（`--lowdata`），报告会上传到公网

### 怎么建（VPS 采集 + Mac 上两条 automation）

**第一层：VPS 侧采集（cron 每 10 分钟，Mac 关机照跑）**

```bash
bash scripts/vps-sentinel-install.sh <凭据别名> --home-ip <家宽出口IP>
```

- 上传 `vps-sentinel-agent.sh` 到 `/usr/local/bin/`，写 `/etc/vps-sentinel.conf`（600），装 `/etc/cron.d/vps-sentinel`
- 每次追加一行 JSON 到 `/var/log/vps-sentinel/sentinel.jsonl`，保留 30 天 / 8000 行自滚动
- 采样分层（省资源）：每次查服务/端口/磁盘/负载/重启；1 小时查出口 IP + 回程 ping；6 小时查证书 + 订阅自取 + 落地风控；24 小时查 IP 风险分 + 回程 AS 路径
- 幂等，可重复跑；`--uninstall` 卸载（保留日志）；`--interval N` 改频率；`--no-landing` / `--no-risk` 关掉外呼

**第二层：Mac 侧判定（两条 automation：日检 + 周检）**

prompt 不要手抄。从凭据文件直接生成，IP / 端口 / 域名 / dest 全部自动填好：

```bash
bash scripts/vps-automation-spec.sh <凭据别名>            # 打印两条规格（人读，照抄即可）
bash scripts/vps-automation-spec.sh <凭据别名> --daily    # 只日检
bash scripts/vps-automation-spec.sh <凭据别名> --weekly   # 只周检
bash scripts/vps-automation-spec.sh <凭据别名> --json     # 机读，直接喂 automation_update
NODE_NAME=MyNode bash scripts/vps-automation-spec.sh <凭据别名>   # 换显示名
```

| automation | 排期 | 跑什么 | 盯什么 |
|---|---|---|---|
| `<别名>节点哨兵-每日检查` | 每天 21:30 | `vps-sentinel-fetch.sh` | 存活 / 延迟 / 出口 IP / 证书余期 / 覆盖率；正常 ≤4 行，异常才展开 |
| `<别名> 质量周检-NodeQuality 对比` | 周一 09:00 | `vps-quality-report.sh --lowdata` + `vps-quality-diff.sh` | IP 风险分 / 解锁 / 三网回程漂移 / 磁盘；有退化退出码 3 |

**两条都要建，别只建日检。** 日检只回答「此刻有没有坏」，周检才回答「这台机器是在变好还是变烂」——观察期结束要判断续费还是退役，靠的是周检攒出来的趋势，不是某一天的快照。首个周检只出基线（快照不足两次会返回 1，属正常），第二周起才有对比。

- 日检：拉回远端日志 → 本机再探测一次 → 合并输出；退出码 `0` 正常 / `1` 警告 / `2` 严重
- 日检周日加 `--risk` 做 IP 风险复检，并追加进工作区当日日志
- 周检：快照自动归档到 `~/.vps-node/reports/<IP下划线>/<时间戳>/`，对比失败不重试，直接报错摘要
- 两条的完整 prompt 正文、占位符说明、阈值位置见 `references/sentinel-prompt.md`

```bash
# 手动先验一次，确认正常再建 automation
bash scripts/vps-sentinel-fetch.sh <凭据别名>            # 服务端摘要 + 本机探测 + 异常聚合
bash scripts/vps-sentinel-fetch.sh <凭据别名> --json     # 机读
bash scripts/vps-sentinel-fetch.sh <凭据别名> --full     # 展开每条异常原始记录
bash scripts/vps-sentinel-fetch.sh <凭据别名> --days 3   # 只看最近 3 天
bash scripts/vps-sentinel-fetch.sh <凭据别名> --no-local # 跳过本机探测（Mac 在其他网络时用）
```

**为什么必须两层**：VPS 自己测自己永远是绿的，看不到「国内 → VPS 被墙 / 被 QoS」——而这恰恰是最影响体感的指标；反过来，只靠 Mac 则关机即断档，观察期数据出现空洞。所以采集常驻 VPS 保证连续性，判定放 Mac 补上真实客户端视角。

`vps-sentinel.sh`（单层旧版）保留可用，适合「现在就要看一眼」的即时检查。

## 深度质量报告（NodeQuality）

**周检 automation 依赖这一节**（每周一次 `--lowdata` 快照）；首次部署时它仍属可选——跑不跑取决于流量是否计费、报告能否公开。

内置检查脚本分工（按时间顺序）：

| 脚本 | 何时跑 | 耗时 | 覆盖 |
|---|---|---|---|
| `vps-precheck.sh` | **第一步（装之前）** | 1-3 分钟 | 验货：硬件 / 虚拟化 / 出网 / 磁盘 IO / 带宽 / IP 情报 / 回程 AS / AI 站连通 |
| `vps-external-ip-check.sh` | 第一步 `--ipaudit` | +1-2 分钟 | IP 纯净度 9 项（ipinfo / Scamalytics / AbuseIPDB / DNSBL） |
| `vps-quality-report.sh` | 第一步 `--deep`（需密钥） | +10-20 分钟 | 硬件跑分 + 流媒体解锁 + 全网测速 + 回程（NodeQuality） |
| `vps-quality-diff.sh` | 质量周检（周一 09:00） | 3 秒 | 拿最近两次 NodeQuality 快照做并排对比（风险分/解锁/延迟/磁盘），有退化返回 3 |
| `vps-verify.sh` | 第五步（验收） | 30 秒 | 端口 / REALITY 证书 / 订阅 / 延迟 / 出口 IP / 可选浏览器 |
| `vps-route-check.sh` | 第五步（验收） | 2 分钟 | 去程 + 回程路由与 ASN 全标注 |
| `vps-sentinel.sh` | 随时（单层即时） | 20 秒 | 服务端存活 / 双协议延迟 / 出口 IP / 证书余期 / 可选风险分 |
| `vps-sentinel-install.sh` | 第六步（验收通过后） | 30 秒 | 装 VPS 侧采集器（cron 每 10 分钟），一次性 |
| `vps-sentinel-fetch.sh` | 每日哨兵 | 30 秒 | 拉回服务端日志 + 本机探测 + 异常聚合 |
| `vps-automation-spec.sh` | 第六步，建 automation 前 | 1 秒 | 从凭据渲染日检 + 周检两条 automation 规格，免手填占位符 |

最后一项封装的是 [LloydAsp/NodeQuality](https://github.com/LloydAsp/NodeQuality)（本质是 Yabs + [xykt IP 质量](https://github.com/xykt) + NetQuality + 融合怪的整合器，在 chroot 沙箱 BenchOS 里跑，无痕）。

```bash
bash scripts/vps-quality-report.sh <IP> <SSH_PORT>              # 默认：快速硬件 + 全量网络
bash scripts/vps-quality-report.sh <IP> <SSH_PORT> --full       # 深度硬件，约 20-35 分钟
bash scripts/vps-quality-report.sh <IP> <SSH_PORT> --lowdata    # 网络测速低流量，按量计费机器用
bash scripts/vps-quality-report.sh <IP> <SSH_PORT> --dry-run    # 只自检环境，不跑测试
```

**跑完自动归档**：脚本会把 xykt 三份分报告（硬件 / IP / 网络，含详细回程版）的 SVG 下载到 `~/.vps-node/reports/<IP下划线>/<时间戳>/`（600），同时用 `vps-quality-parse.py` 从日志抽出 `metrics.json`（结构化指标）。上游既没有公开保留策略也没有删除接口，**要做前后对比只能靠这份本地副本**，别指望那条 `nodequality.com/r/xxx` 链接长期有效。

**对比两次快照**：

```bash
bash scripts/vps-quality-diff.sh <凭据别名>          # 最近两次并排比，有退化退出码 3
bash scripts/vps-quality-diff.sh <凭据别名> --all     # 列出全部快照
bash scripts/vps-quality-diff.sh <凭据别名> --json    # 机读，给 automation 用
```

判定阈值集中在 `vps-quality-diff.py` 顶部：三网漂移 30ms、国际互连 20ms、风险分 +5、磁盘 +10% 分别记退化。缺 `metrics.json` 时会自动从同期日志现场解析补出来。

**周检 automation 就用这条链路**：`--lowdata` 出快照 → 自动归档 → `vps-quality-diff.sh` 比对。prompt 由 `vps-automation-spec.sh --weekly` 生成（见第六步），模板正文在 `references/sentinel-prompt.md`。

**编排器默认不跑它**（要 `vps-precheck.sh --deep` 才跑），原因是三件事会推翻「12 分钟交付」的假设：

1. **耗时**：Yabs 磁盘测试 + 多节点测速，10-20 分钟起
2. **流量**：全量网络测速约 2-3GB，`--lowdata` 也要 300MB-1GB
3. **公开上传**：上游无条件把结果 zip POST 到 `api.nodequality.com`，返回一个公开链接（`nodequality.com/r/xxx`）。要保留报告只能靠这个链接——脚本跑完会 `rm -rf` 本地结果

所以要跑之前，先跟用户确认这三件事，尤其是流量是否计费、报告能否公开。

失败常见原因：LXC/OpenVZ 容器（chroot 受限）、磁盘不足 1.8GB、中途断网。超时中断后确认 `mount | grep nodequality`，有残留就 `umount -R` 后删目录。

## 可选：挂住宅上游出口（Webshare 静态住宅等）

机房 IP 做 AI 出口容易被风控盯上；买一条静态住宅代理挂在节点后面，让 TCP 流量从住宅 IP 出去，是性价比最高的解法。以 Webshare Static Residential 为例：

**1. 先实测，确认了才动配置**（在 VPS 上）：

```bash
curl -s --max-time 12 -x "socks5h://<user>:<pass>@<host>:<port>" https://api.ipify.org   # 应返回代理 IP
curl -s --max-time 12 -x "socks5h://<user>:<pass>@<host>:<port>" "http://ip-api.com/json/?fields=isp,org,proxy,hosting"
# isp 应是家宽运营商（Charter/Comcast 等），proxy=false hosting=false 才算干净
```

**2. 改 sing-box 配置**（备份 → 加出站 → 改 final → check → 重启）：

```json
{ "type": "socks", "tag": "webshare-us", "server": "<host>", "server_port": <port>,
  "version": "5", "username": "<user>", "password": "<pass>" }
```

`route.final` 指向它，但**必须加一条 UDP 直连规则**排在前面：

```json
"route": { "rules": [ { "network": "udp", "outbound": "direct" } ], "final": "webshare-us" }
```

**3. 必须知道的三件事**：

- **SOCKS5 ≠ 支持 UDP**：Webshare 的 SOCKS5 只代理 TCP，UDP ASSOCIATE 会被拒（日志报 `socks5: request rejected, code=7`）。上面那条 UDP→direct 规则就是为此而加，QUIC 从机房 IP 直连出去即可，无风控问题
- **按流量计费**：final 指过去之后所有 TCP 流量都烧住宅套餐额度，跑满即断网。介意就把 final 留在 direct，用按域名的 rules 只分流 AI 站
- **延迟 +60-90ms**：多一跳 VPS→代理落地的绕行（实测：洛杉矶→阿什本 73ms、洛杉矶→湾区 13ms，节点总延迟差 60-90ms）

**4. 改完同步改基线**，否则哨兵当天就误报「出口 IP 变更」：

- 凭据 `<sub>.json` 加 `egress_ip: <代理出口IP>`（哨兵和 verify 都优先认它，没有才回落到 VPS IP）
- `config.json` 现在**含代理密码**，`chmod 600`
- 凭据里顺手记一个 `webshare: {host, port, user, pass, since}` 块，换机重配或回滚都从这抄

**回滚**：还原 `/etc/sing-box/config.json.bak-before-webshare` 并重启；或删掉 `webshare-us` 出站、`route.final` 改回 `direct`、删掉 UDP 规则。凭据里的 `egress_ip` 字段同步删掉。

### 双出口主备（同一商家买多条 IP）

再买一条时按同样流程实测，然后加第二个 socks 出站，并把出口做成一个可切换的组：

```json
{ "type": "urltest", "tag": "webshare-auto", "outbounds": ["webshare-us", "webshare-us2"],
  "url": "https://www.gstatic.com/generate_204", "interval": "5m", "tolerance": 50 },
{ "type": "selector", "tag": "webshare", "outbounds": ["webshare-auto", "webshare-us", "webshare-us2"],
  "default": "webshare-auto" }
```

`route.final` 指向 selector（`webshare`），另加 clash_api 供切换：

```json
"experimental": { "clash_api": { "external_controller": "127.0.0.1:9090", "default_mode": "rule" } }
```

- **`urltest` = 自动主备**：常态选 RTT 低的（湾区 13ms 会压过 Ashburn 73ms），一条挂了自动切到另一条，无需人工干预
- **手动切换**（SSH 到 VPS）：
  ```bash
  # 钉死 Ashburn / 钉死湾区 / 恢复自动
  curl -s -X PUT http://127.0.0.1:9090/proxies/webshare -d '{"name":"webshare-us"}'
  curl -s -X PUT http://127.0.0.1:9090/proxies/webshare -d '{"name":"webshare-us2"}'
  curl -s -X PUT http://127.0.0.1:9090/proxies/webshare -d '{"name":"webshare-auto"}'
  # 查当前选中
  curl -s http://127.0.0.1:9090/proxies/webshare
  ```
- **凭据基线**：`egress_ip` 填**逗号分隔的多值**（如 `<住宅IP-A>,<住宅IP-B>`），sentinel.sh 与 verify.sh 的比对逻辑都支持列表
- **同商家多条 IP = 同一 ASN**，只是多出口，不做身份多样化；要多样化需跨商家/跨 ASN
- **带宽额度按套餐共享**：两条 IP 烧同一份额度，不是各自一份
- 挑 IP 时注意 Proxy List 里**每条的端口可能不同**（同一账号下不同 IP 的端口常不一样），IP 也可能只差一位，配置前必须照抄列表行

**回滚**：还原 `/etc/sing-box/config.json.bak-before-webshare` 并重启；或删掉 `webshare-us` 出站、`route.final` 改回 `direct`、删掉 UDP 规则。凭据里的 `egress_ip` 字段同步删掉。

## IP 体检（购买前 / 购买后）

原理一句话：报告测的是「**测试服务器实际看到的出口 IP**」，所以只要让流量从目标 IP 出去就行，不需要先把它配置到机器上。据此分三种入口。

| 时机 | 你手上有什么 | 用什么 | 能测到 |
|---|---|---|---|
| **购买前** | 只有一个**裸 IP**（试用、别人给的、还没买） | `ip-check-lite.sh <IP>` | 静态项：归属 / IP 类型 / 风险评分 / 风险因子（免注册三源：ipinfo + IPLogs + Scamalytics） |
| **购买后·情况一** | **代理型 IP**：有 socks5/http 凭据，IP 未配进任何机器 | `ip-audit.sh --proxy 'socks5h://user:pass@host:port' --expect <IP> [--node <别名>]` | 全六节（含流媒体/AI 解锁、423 库黑名单、IPQS） |
| **购买后·情况二** | **纯 VPS**：有 SSH | `ip-audit.sh --vps-ip <IP> --vps-port <端口>` | 全六节 |
| 已配进本 skill 的出站 | 凭据别名 + egress 名 | `ip-audit.sh --node <别名> --egress us1` | 全六节（凭据从 VPS 侧解析，不落本地明文） |

**为什么购买前只能查静态项**：第五、六节要真实向 TikTok / Netflix / ChatGPT / 25 端口发起探测，没有可用的出口 IP 就没有观测点，这不是脚本限制，是物理限制。

### 判定阈值（沿用挑 Webshare IP 时定的标准）

| 指标 | 通过 | 复核 | 放弃 |
|---|---|---|---|
| Scamalytics Fraud Score | ≤ 10 | 11–25 | > 25 |
| IPLogs verdict | `clean` | — | 其它值 |
| IPQS | 0–10 | 11–75 | > 75（「可疑」档） |
| 代理 / VPN / Tor / 滥用 / 机器人 | 全部「否/无」 | 单一库阳性可接受 | 多库同时阳性 |
| IP 类型 | 多数库判「家宽」 | 一半对一半 | 多数判「机房」 |

`ip-check-lite.sh` 退出码 0 = 可继续下一步，1 = 需要人工复核。过了快查再花钱/花时间跑全量。

### 三条硬规矩

- **DNSBL 必须跑在 VPS 上**：本机走 Clash TUN 的 fake-ip（198.18.x），DNSBL 查出来全是无效结果。所以 `--proxy` 模式默认经 VPS 转发执行，`--local` 只作应急
- **`--expect` 不要省**：同一商家多条 IP 时极易搞混（实测出现过两条 IP 只差最后一位、端口还不同的情况），出口 echo 不等于期望值就中止，避免把 A 的报告当成 B 的
- **报告公开且不可撤回**：`Report.Check.Place` 只露掩码 IP / ASN / 评分，不含完整 IP，但没有删除接口。本地留档在 `~/.vps-node/ipaudits/<出口IP>/`



| 现象 | 原因 | 处理 |
|---|---|---|
| `缺少 expect` | macOS 未装（密码登录模式需要） | `brew install expect`，或改用 `--key` |
| 预检报「SSH 认证失败」 | 密码错 / 端口错 / 机器没起来 | `nc -vz <IP> <PORT>` 先确认端口通 |
| 预检报「OpenVZ / LXC」 | 容器化 VPS | 换 KVM 机型，或 `FORCE=1` 接受没有 BBR |
| 预检回程全是 `*` | 目标不响应 ICMP | 换 `TARGET=<家宽IP>` 或 `114.114.114.114` 再试 |
| 预检判 FAIL 但你想硬上 | 已知风险可接受 | `FORCE=1 bash bootstrap-new-vps.sh ...` |
| `duckdns update failed` | token 错 / 子域名未在网页添加 | 去 duckdns.org 确认 Domains 列表 |
| acme.sh 签发失败 | DNS 未传播 / LE 限流 | 脚本已自动 `--force` 重试一次；仍失败等 5 分钟重跑 `--issue` |
| 第 4 步密钥登录失败 | authorized_keys 权限 / sshd 配置 | 脚本会中止且不加固，重新跑即可 |
| 加固后 SSH 断开 | ufw 未放行 SSH | 用 VPS 控制台 VNC 进 `ufw disable`；脚本本有防锁死校验，出现即查 `SSH_PORT` 参数是否与实际一致 |
| 订阅 404 | 端口没放行 / 服务名不符 / token 不匹配 | `systemctl status vps-sub-https`、`ufw status`、`ls /opt/vps-sub` |
| REALITY 证书是自签 | dest 不支持 TLS1.3 或 H2 | 换 dest 站点，改 init 脚本 `DEST` 后重跑配置段 |
| Verge 没出现新卡片 | 深链未生效 | Verge → 配置 → 新建 → 从 URL 导入 `<SUBURL>` |
| 延迟测不出 | 卡片未激活 | 先点卡片 |

## 端口 / 文件清单

| 端口 | 协议 | 用途 |
|---|---|---|
| SSH_PORT | tcp | SSH（ufw limit，30 秒 6 次即封） |
| 443 | tcp | VLESS+REALITY（xtls-rprx-vision） |
| 8443 | udp | Hysteria2 |
| 2096 | tcp | HTTPS 订阅（仅 `/<token>.yaml` 可达，TLS1.2+） |

VPS 侧：`/etc/sing-box/config.json`、`/opt/vps-sub/<token>.yaml`、`/opt/vps-certs/`、`/opt/serve_sub_https.py`、`/etc/systemd/system/vps-sub-https.service`、`/etc/ssh/sshd_config.d/99-hardening.conf`、`/etc/sysctl.d/99-hardening.conf`、`/etc/fail2ban/jail.local`

服务端哨兵（装了才有）：`/usr/local/bin/vps-sentinel-agent.sh`、`/etc/vps-sentinel.conf`（600）、`/etc/cron.d/vps-sentinel`、`/var/log/vps-sentinel/sentinel.jsonl`（600，30 天 / 8000 行自滚动）

本机侧：`~/.vps-node/<sub>.json`（凭据）、`~/.vps-node/<sub>-sentinel.jsonl`（拉回的服务端日志）、`~/.vps-node/<sub>-{audit,harden,quality}-*.log`、`~/.ssh/id_ed25519_vps`

`<sub>.json` 字段：`ip` / `fqdn` / `sub_url` / `uuid` / `reality_pub` / `short_id` / `dest` / `hy2_pass` / `singbox` / `subsvc` / `sub_http` / `ssh_port` / `home_ip` / `deploy_date` / `egress_ip`（挂住宅上游时才有，经节点期望看到的出口）。哨兵、验收、路由、周检、automation 生成五个环节都从这里读参数，所以**换机器只要换这个文件**。`deploy_date` 用来算观察期结束日（部署 + 7 天），缺失时生成的 prompt 会省略那句提醒。

## 单跑子脚本

```bash
# 只验货，不装任何东西（买了新机器先跑这个）
bash scripts/vps-precheck.sh <IP> <SSH_PORT> '<ROOT_PASS>'

# 只做安全加固（对已有 VPS）
scp scripts/vps-harden.sh root@IP:/root/ && ssh root@IP 'SSH_PORT=22 bash /root/vps-harden.sh'

# 只做 IP 体检
bash scripts/vps-external-ip-check.sh <IP> 443

# ---- IP 体检三阶段（详见「IP 体检」一节）----
# 购买前：只有裸 IP，免注册三源快查
bash scripts/ip-check-lite.sh <IP>
# 购买后·情况一：有代理凭据，经 VPS 转发跑全六节（凭据自动转义）
bash scripts/ip-audit.sh --proxy 'socks5h://user:pass@host:port' --expect <IP> --node <凭据别名>
# 购买后·情况二：纯 VPS，直接上去跑
bash scripts/ip-audit.sh --vps-ip <IP> --vps-port 22
# 已配进本 skill 出站：按 egress 名复测（凭据从 VPS 侧取）
bash scripts/ip-audit.sh --node <凭据别名> --egress us1

# 深度质量报告
bash scripts/vps-quality-report.sh <IP> <SSH_PORT> --lowdata

# 即时检查（单层，不依赖 VPS cron）
bash scripts/vps-sentinel.sh <凭据别名> --risk

# 装 / 卸 VPS 侧采集器（只在验收全绿后装）
bash scripts/vps-sentinel-install.sh <凭据别名> --home-ip <家宽IP>
bash scripts/vps-sentinel-install.sh <凭据别名> --uninstall

# 拉服务端日志做每日分析
bash scripts/vps-sentinel-fetch.sh <凭据别名>

# 生成两条 automation 的规格（免手填占位符）
bash scripts/vps-automation-spec.sh <凭据别名>            # 人读
bash scripts/vps-automation-spec.sh <凭据别名> --json     # 机读

# 周检手动跑一次（等价于 weekly automation 做的事）
bash scripts/vps-quality-report.sh <IP> <SSH_PORT> --lowdata && \
bash scripts/vps-quality-diff.sh <凭据别名>

# 改完脚本准备提交前：语法 + 敏感值自检（退出码 0 才算干净）
bash scripts/repo-lint.sh
```

## 已知限制

- **预检会装 `nexttrace`**：看回程 AS 路径必须有它（mtr 对无 PTR 的跳显示 `AS???`，会把 AS10099 / AS9929 吞掉造成误判）。装不上则退 mtr 并在结论里注明工具名
- **预检不查 Scamalytics / AbuseIPDB**：这两家要浏览器渲染解析，只在部署后的 `vps-external-ip-check.sh` 里做。预检用 ip-api + proxycheck 两个免费 API 快速判。更新：`ip-check-lite.sh` 已能直接抓 Scamalytics 页面（无需浏览器），但 **AbuseIPDB 免注册页对脚本返回 403**（Cloudflare 挡 curl），只能浏览器手查或注册免费 key（约 5000 次/月）后接进脚本
- **预检判 FAIL 可用 `FORCE=1` 强推**：比如你明知道是 OpenVZ 但仍要装（BBR 用不了）、或 443 被自己另一个服务占着。强推时警告照样打印
- **Hysteria2 的 UDP 8443 无法自动验证**，只能靠实际连通判断
- 体检里的 ipinfo / Scamalytics / AbuseIPDB 依赖本机 Clash 代理 + Chrome headless；代理端口自动探测（7897/7890/7891/1087），可用 `IPCHECK_PROXY=` 覆盖
- 证书 90 天有效期由 acme.sh cron 自动续期，无需干预
- 加固刻意**未做**：建 sudo 用户并禁 root、auditd、lynis。如需更严合规可另加
- **NodeQuality 结果一律公开、且不可撤回**：`/result/*` 打 zip 后 base64 POST 到 `api.nodequality.com`，返回 `nodequality.com/r/<随机串>`；xykt 三份分报告另存在 `Report.Check.Place`。2026-11 实测暴露面：
  - 公开可读（无需任何验证，直接 curl 就 200）：掩码 IP（`a.b.*.*`，只藏后两段）、ASN 与组织、城市、CPU/内存/磁盘规格、解锁清单、三网回程路径、上游对等 AS 列表
  - 需过 Cloudflare Turnstile 才能看：nodequality 汇总页（无 token 一律 403）；其 zip 含 xykt 原始输出与回程 JSON，**未做脱敏**，这是唯一说不准的部分
  - 完全不出现：完整 IP、主机名、DuckDNS 域名、SSH 端口、UUID / REALITY 密钥 / Hy2 密码（这些脚本不读 sing-box 配置）
  - 前端只有 `record` / `searchRecord` / `setprovider`，**没有删除接口** —— 链接一旦产生就撤不回来
  - 所以：只自己留用、别外传链接；要和别人比价/求诊断，先想清楚 ASN + 城市 + 解锁指纹足以定位到商家和机房。对暴露零容忍就改用 `vps-external-ip-check.sh` + `vps-route-check.sh`，两者只在本地产出
- NodeQuality 上游是第三方远程脚本（`run.NodeQuality.com`），每次执行取最新版；非交互依靠 stdin 喂 4 个答案（`f/y/y/y`），上游若改交互顺序需同步调整 `ANSWERS`
- **NodeQuality 的「国内测速」在境外 VPS 上必然全 ERROR**（2026-11 实测）：该模块用 Ookla speedtest CLI 指定国内节点 ID，但 Ookla 节点库对境外查询按地理位置过滤——`servers?id=5396` 直接返回美国节点，CLI 报 `NoServersException`，六个节点全军覆没。不是 VPS 的网络问题；国内三网真实质量看「三网 TCP 大包延迟」和「回程路由」两节就够。国内 VPS 上此节正常
- **服务端哨兵看不到「国内 → VPS 被墙 / 被 QoS」**：它从 VPS 内部测自己，永远正常。这个视角只能靠 `vps-sentinel-fetch.sh` 在 Mac 上补做——所以 Mac 长期不开机时，别只看服务端日志说「一切正常」
- **服务端哨兵依赖 cron 存活**：cron 被停/被系统清理后日志会静默停止增长。`fetch` 会算覆盖率，<90% 就提示检查 `systemctl status cron`
- **`--home-ip` 是动态的**：家宽 IP 变了回程 ping 会全空（日志里 `cping=""`）。重跑 install 或改 `/etc/vps-sentinel.conf` 的 `HOME_IP` 即可
- **落地风控探测（claude.ai / chatgpt.com）6 小时一次**：不更频繁是为了不在目标站留下高频机器人痕迹
- **哨兵是 automation，不是 skill 的一部分**：skill 提供脚本 + `vps-automation-spec.sh` 生成的 prompt 文本，automation 本体要通过 automation 工具单独创建（**日检 + 周检各一条**）。换机器时要建新的一对；旧机器退役后两条都停掉，否则会一直报红（日检报连不上、周检报 SSH 失败）
- 密钥按 `id_ed25519_vps`（本 skill 统一键）→ `id_ed25519_<凭据别名>` → `id_ed25519_<子域名首段>` → 任意 `id_ed25519_*` → `id_ed25519` → `id_rsa` 顺序探测，都没有则走默认 ssh 配置；端口按凭据 `ssh_port` → 22 → 2222 逐个试。手工建过的机器密钥名不统一（历史机器可能用 `id_ed25519_<其它别名>`），靠后两级兜底，不必改脚本
