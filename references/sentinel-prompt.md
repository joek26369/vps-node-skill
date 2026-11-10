# 哨兵 automation 模板（日检 + 周检）

**只在验收全绿之后做这一步。** 先 `bash scripts/vps-sentinel-install.sh <凭据别名> --home-ip <家宽IP>` 装好采集器。

**不要手抄下面的模板。** 用脚本生成，占位符会从 `~/.vps-node/<别名>.json` 自动填好：

```bash
bash scripts/vps-automation-spec.sh <凭据别名>          # 两条规格一起打印
bash scripts/vps-automation-spec.sh <凭据别名> --json   # 机读，直接喂 automation_update
```

**本文件是说明与理由，`vps-automation-spec.sh` 里的 prompt 才是实际下发的那份。** 要改措辞就改脚本，别只改这里，否则两边会走偏。

需要建的是**两条**：日检（每天 21:30，看此刻有没有坏）+ 周检（周一 09:00，看质量趋势）。

## 建议参数

- `name`: `<节点名>节点哨兵-每日检查`
- `scheduleType`: `recurring`
- `rrule`: `FREQ=DAILY;BYHOUR=21;BYMINUTE=30`（晚高峰后，可换 8:00 看早间）
- `status`: `ACTIVE`

## 架构前提：双层哨兵

| 层 | 在哪跑 | 频率 | 负责 |
|---|---|---|---|
| 采集层 | VPS（cron） | 每 10 分钟 | 机器活着吗、端口在听吗、出口 IP 变了没、证书还剩几天、回程延迟与 AS 路径、落地风控 |
| 判定层 | Mac（本 automation） | 每天 1 次 | 拉回日志做趋势分析 + 做一次**真实客户端探测** |

**为什么不能只用一层**：VPS 自己测自己永远绿，看不到「国内 → VPS 被墙 / 被 QoS」——这恰恰是用户最在意的指标；而 Mac 侧一旦关机就断档。所以采集常驻 VPS，判定放在 Mac，Mac 开机时补上真实视角，关机期间数据也不丢。

## prompt 正文模板（示例，实际下发以脚本输出为准）

```
对 <节点名>（<IP>）做每日节点体检，用简体中文输出（正常 ≤4 行，异常才展开）。

执行（Mac 本机，不需要询问）：
bash ~/.workbuddy/skills/vps-node/scripts/vps-sentinel-fetch.sh <凭据别名>

该脚本做两件事：
1) 从 VPS 拉回服务端哨兵日志（cron 每 10 分钟采集，Mac 关机期间照常写入）
2) 在 Mac 上做一次真实探测（唯一能看到「国内 → VPS 是否连通」的视角）
输出 = 服务端摘要 + 本机探测 + 异常聚合；退出码 0 正常 / 1 警告 / 2 严重。

报告规则：
- 0 → 四行内汇总：样本覆盖率 / 回程延迟中位 / 出口 IP / 证书天数 / 本机 REALITY 延迟
- 1 或 2 → 逐条列出异常聚合行（脚本已按类型归并并给出首末时间），每条补一句后果判断
- 出口 IP 变更 → 立即提醒开工单固定 IP；同时提示「住宅 IP 的全部溢价已归零」
- 落地风控出现 chatgpt=403 / anthropic=403 → IP 已被目标站风控，请用户先用真浏览器复核
  再决定是否换 IP（headless 结论可能与真浏览器不同）
- SSH 不可达（拉不到服务端日志）→ 先看本机探测结果：本机也不通才判节点故障；
  本机通说明可能只是 VPS 侧 SSH 端口被封，单列一条提醒
- 覆盖率 <90% → 提示 cron 可能没跑：ssh -p <SSH端口> root@<IP> 'systemctl status cron; cat /etc/cron.d/vps-sentinel'
- 如果今天是周日，改用 `vps-sentinel-fetch.sh <凭据别名> --risk`，并把结论追加写入工作区日志
  .workbuddy/memory/ 当天文件（先读再追加，不要覆盖）

背景：<节点名> 是 <购买日期> 部署的 <服务商><线路> VPS，sing-box 双协议
（VLESS+REALITY 443 dest=<dest>、Hysteria2 8443），订阅 HTTPS 端点 <域名>:2096，
用于 Claude/ChatGPT 等 AI 出口。<观察期结束日期> 应提醒用户做观察期总结评估。
```

## 填参说明

| 占位符 | 取值 |
|---|---|
| `<节点名>` | 与 `~/.vps-node/<sub>.json` 的 fqdn 前缀一致，便于对号 |
| `<IP>` | VPS 公网 IPv4 |
| `<凭据别名>` | 部署时 bootstrap 写入的 `~/.vps-node/<duckdns子域名>.json` |
| `<SSH端口>` | 实际 SSH 端口 |
| `<dest>` | REALITY 借壳站点 |
| `<域名>` | `<子域名>.duckdns.org` |
| `<观察期结束日期>` | 部署日 + 7 天（凭据里有 `deploy_date` 时由脚本自动算，没有就省略这句） |

脚本从凭据文件取 `ip` / `ssh_port` / `fqdn` / `dest` / `deploy_date`（后两项缺省为 `www.paypal.com` 与省略）。显示名默认用凭据别名，可用 `NODE_NAME=` 覆盖；排期可用 `DAILY_RRULE=` / `WEEKLY_RRULE=` 覆盖。

## 为什么不把检查逻辑写进 prompt

早期版本把每条 `ssh` / `curl` 命令都写死在 prompt 里，结果有三个问题：

1. 换一台机器就要重抄一遍，密钥路径、端口、socket 路径都不同
2. prompt 里 `Bearer set-your-secret` 这类值散落在文本中，泄漏面大
3. 上游接口变了要改 automation 本身，改错了哨兵就静默失灵

现在 prompt 只调用 `vps-sentinel-fetch.sh`，判定与阈值全部集中在脚本里，改脚本即可，automation 不用动。

## 为什么采集要放 VPS

| 只放 Mac 的问题 | 放 VPS 后 |
|---|---|
| Mac 关机 / 合盖 / 断网 → 当天没有样本，观察期出现空洞 | 7×24 连续采样，观察期数据完整 |
| 本机 Clash TUN 会劫持探测流量（踩过：traceroute 全 `*`） | 服务端无代理干扰，回程路径干净 |
| 每次都要开着 Verge 才能测延迟 | 不需要 Mac 参与，也不需要节点处于选中状态 |
| 只能看「此刻」，看不到「这三天哪天开始变差」 | 有完整时间序列，能定位劣化起点 |

代价是 VPS 侧多一份只读 cron（约 20 行 JSON / 10 分钟，30 天约 1.5MB），以及安装时要做一次 SSH 写操作（装脚本 + cron）。

---

# 周检 automation：质量趋势（第二条，必建）

日检看「此刻有没有坏」，周检看「这台机器是在变好还是变烂」。周检跑一次 NodeQuality 低流量快照，自动归档，再和上一份比。**和日检是两条独立的 automation**，排期不同、脚本不同、结论不同。

## 建议参数

- `name`: `<节点名> 质量周检-NodeQuality 对比`
- `scheduleType`: `recurring`
- `rrule`: `FREQ=WEEKLY;BYDAY=MO;BYHOUR=9;BYMINUTE=0`（周一早上；改 `BYDAY=SU` 可换周日）
- `status`: `ACTIVE`

## prompt 模板（示例，实际下发以脚本输出为准）

```
对 <节点名> 节点（<IP>，SSH 端口 <SSH端口>，凭据别名 <凭据别名>）做每周质量快照，并与上一次快照对比，输出中文简报。

【执行步骤】
1. 先跑一次 NodeQuality 低流量快照（约 8-15 分钟，流量 300MB-1GB）：
   bash ~/.workbuddy/skills/vps-node/scripts/vps-quality-report.sh <IP> <SSH端口> --lowdata
   说明：脚本会自动把硬件/IP/网络三份 SVG + metrics.json 归档到 ~/.vps-node/reports/<IP下划线>/<时间戳>/，
   并返回一条 nodequality.com 链接（公开且不可撤回，只写进报告，不要外发）。

2. 跑对比：
   bash ~/.workbuddy/skills/vps-node/scripts/vps-quality-diff.sh <凭据别名>
   退出码：0=无退化 / 3=存在退化项 / 1=快照不足两次（首次运行正常）/ 2=参数错。
   只有一次快照时，只报基线数值，说明下周起才有对比。

3. 按脚本给的阈值下结论（不要自己另算）：
   - 退化项（🔴）逐条说明变化值与可能原因，重点解释四类：
     Scamalytics/AbuseIPDB 上涨（IP 被滥用或标记）、ChatGPT 等解锁掉了（进目标站风控）、
     联通/移动回程漂移 ≥30ms（线路调度或拥塞）、磁盘占用涨 ≥10%（日志或缓存堆积）
   - 关注项（🟡）一句话带过
   - 无退化时明确说「本周无退化」，并给一行「联通/移动回程 + 硬件」关键数值

【输出格式】中文，不超过 25 行：结论行 → 退化项表格（指标|基线|本次|变化|判断）→ 2-3 条可执行建议 → 快照目录与本次链接

【注意】
- 不重复日检内容（存活、延迟、证书、出口 IP 漂移）
- SSH 连不上就报告「周检无法执行 + 错误摘要」并结束，不要重试超过一次
- 磁盘可用 < 2GB 时跳过 NodeQuality，只提示清理
- 不要改服务器配置、不要重启任何服务
```

## 为什么周检单独一条 automation，而不是塞进日检

| 塞进日检的问题 | 分开之后 |
|---|---|
| NodeQuality 要 8-20 分钟、300MB-1GB 流量，天天跑既慢又费流量 | 一周一次，流量可控 |
| 日检的 prompt 会变长，判定逻辑混在一起，改一处怕碰坏另一处 | 各管各的，脚本各自可测 |
| 快照只有两份以上才有对比意义，日跑会攒一堆噪声 | 周节奏刚好对上「线路/风控是否劣化」的观察尺度 |

## 阈值改哪里

全在 `scripts/vps-quality-diff.py` 顶部：`TH_LAT`（三网漂移）、`TH_INTL`（国际互连）、`TH_RISK`（风险分）、`TH_DISK`（磁盘）。改脚本即可，automation 不用动。

