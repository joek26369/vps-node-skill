#!/bin/bash
# vps-automation-spec.sh — 从凭据文件生成两条哨兵 automation 的完整规格
#
# 用途：新建机器后不用手抄 prompt、不用替换占位符。脚本从 ~/.vps-node/<别名>.json
#       读出 ip / ssh_port / fqdn / dest，渲染出「日检」和「周检」两条 automation
#       的 name / rrule / prompt，直接喂给 automation_update 即可。
#
# 用法：
#   bash vps-automation-spec.sh <凭据别名>              # 两条都打印（人读）
#   bash vps-automation-spec.sh <凭据别名> --daily      # 只日检
#   bash vps-automation-spec.sh <凭据别名> --weekly     # 只周检
#   bash vps-automation-spec.sh <凭据别名> --json       # 机读，json 数组
#   环境变量：NODE_NAME=MyNode 覆盖节点显示名（默认取凭据别名）
#            DAILY_RRULE / WEEKLY_RRULE 覆盖默认排期
#            VPS_NODE_DIR 覆盖凭据目录（默认 ~/.vps-node）
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CREDDIR="${VPS_NODE_DIR:-$HOME/.vps-node}"
MODE="all"
JSONOUT=0

for a in "$@"; do
  case "$a" in
    --daily)  MODE="daily" ;;
    --weekly) MODE="weekly" ;;
    --json)   JSONOUT=1 ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    -*) echo "未知参数: $a"; exit 2 ;;
    *)  ALIAS="$a" ;;
  esac
done

[ -n "${ALIAS:-}" ] || { echo "用法: bash $0 <凭据别名> [--daily|--weekly|--json]"; exit 2; }
[ -f "$CREDDIR/$ALIAS.json" ] || { echo "❌ 找不到凭据: $CREDDIR/$ALIAS.json"; echo "   部署成功才会有这个文件；先跑 bootstrap-new-vps.sh"; exit 2; }

jsonf() {
  python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],''))" "$CREDDIR/$ALIAS.json" "$1" 2>/dev/null
}

IP=$(jsonf ip)
PORT=$(jsonf ssh_port)
FQDN=$(jsonf fqdn)
DEST=$(jsonf dest)
DDAY=$(jsonf deploy_date)
NODE_NAME="${NODE_NAME:-$ALIAS}"
[ -n "$PORT" ] || PORT=22
[ -n "$DEST" ] || DEST="www.paypal.com"
FQDN_DESC="${FQDN:-（凭据未记录域名）}"

[ -n "$IP" ] || { echo "❌ 凭据里没有 ip 字段: $CREDDIR/$ALIAS.json"; exit 2; }

# 观察期 = 部署日 + 7 天（凭据里没有 deploy_date 就省略这句）
OBS=""
if [ -n "$DDAY" ]; then
  OBS=$(python3 - "$DDAY" <<'PY'
import sys, datetime
try:
    d = datetime.date.fromisoformat(sys.argv[1][:10]) + datetime.timedelta(days=7)
    print(d.isoformat())
except Exception:
    print('')
PY
)
fi

DAILY_RRULE="${DAILY_RRULE:-FREQ=DAILY;BYHOUR=21;BYMINUTE=30}"
WEEKLY_RRULE="${WEEKLY_RRULE:-FREQ=WEEKLY;BYDAY=MO;BYHOUR=9;BYMINUTE=0}"

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# ---------- 日检 ----------
cat > "$TMP/daily" <<EOF
对 ${NODE_NAME}（${IP}）做每日节点体检，用简体中文输出（正常 ≤4 行，异常才展开）。

执行（Mac 本机，不需要询问）：
bash ~/.workbuddy/skills/vps-node/scripts/vps-sentinel-fetch.sh ${ALIAS}

该脚本做两件事：
1) 从 VPS 拉回服务端哨兵日志（cron 每 10 分钟采集，Mac 关机期间照常写入）
2) 在 Mac 上做一次真实探测（唯一能看到「国内 → VPS 是否连通」的视角）
输出 = 服务端摘要 + 本机探测 + 异常聚合；退出码 0 正常 / 1 警告 / 2 严重。

报告规则：
- 0 → 四行内汇总：样本覆盖率 / 回程延迟中位 / 出口 IP / 证书天数 / 本机 REALITY 延迟
- 1 或 2 → 逐条列出异常聚合行（脚本已按类型归并并给出首末时间），每条补一句后果判断
- 出口 IP 变更 → 立即提醒开工单固定 IP；同时提示「住宅 IP 的全部溢价已归零」
- 落地风控出现 chatgpt=403 / anthropic=403 → IP 已被目标站风控，请用户先用真浏览器复核，
  再决定是否换 IP（headless 结论可能与真浏览器不同）
- SSH 不可达（拉不到服务端日志）→ 先看本机探测结果：本机也不通才判节点故障；
  本机通说明可能只是 VPS 侧 SSH 端口被封，单列一条提醒
- 覆盖率 <90% → 提示 cron 可能没跑：ssh -p ${PORT} root@${IP} 'systemctl status cron; cat /etc/cron.d/vps-sentinel'
- 如果今天是周日，改用 bash ~/.workbuddy/skills/vps-node/scripts/vps-sentinel-fetch.sh ${ALIAS} --risk，
  并把结论追加写入工作区日志 .workbuddy/memory/ 当天文件（先读再追加，不要覆盖）

背景：${NODE_NAME} 是 ${FQDN_DESC} 对应的 VPS，sing-box 双协议（VLESS+REALITY 443 dest=${DEST}、
Hysteria2 8443），订阅 HTTPS 端点 :2096，用于 Claude/ChatGPT 等 AI 出口。${OBS:+${OBS} 应提醒用户做观察期总结评估。}
EOF

# ---------- 周检 ----------
cat > "$TMP/weekly" <<EOF
对 ${NODE_NAME} 节点（${IP}，SSH 端口 ${PORT}，凭据别名 ${ALIAS}）做每周质量快照，并与上一次快照对比，输出中文简报。

【执行步骤】
1. 先跑一次 NodeQuality 低流量快照（约 8-15 分钟，流量 300MB-1GB）：
   bash ~/.workbuddy/skills/vps-node/scripts/vps-quality-report.sh ${IP} ${PORT} --lowdata
   说明：脚本会自动把硬件/IP/网络三份 SVG + metrics.json 归档到 ~/.vps-node/reports/ 下，
   并返回一条 nodequality.com 链接（公开且不可撤回，只写进报告，不要外发）。

2. 跑对比：
   bash ~/.workbuddy/skills/vps-node/scripts/vps-quality-diff.sh ${ALIAS}
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
EOF

if [ "$JSONOUT" = "1" ]; then
  SEL="$MODE"
  python3 - "$TMP" "$NODE_NAME" "$DAILY_RRULE" "$WEEKLY_RRULE" "$SEL" <<'PY'
import json, sys
tmp, node, dr, wr, sel = sys.argv[1:6]

def rd(p):
    return open(p, encoding='utf-8').read().rstrip('\n')

specs = [
    ('daily',  f'{node}节点哨兵-每日检查',           dr, rd(tmp + '/daily')),
    ('weekly', f'{node} 质量周检-NodeQuality 对比', wr, rd(tmp + '/weekly')),
]
out = [{'kind': k, 'name': n, 'scheduleType': 'recurring', 'rrule': r,
        'status': 'ACTIVE', 'prompt': p}
       for k, n, r, p in specs if sel in ('all', k)]
print(json.dumps(out, ensure_ascii=False, indent=2))
PY
  exit 0
fi

say_daily() {
  echo "═══════════════ 日检 automation ═══════════════"
  echo "name:         ${NODE_NAME}节点哨兵-每日检查"
  echo "scheduleType: recurring"
  echo "rrule:        ${DAILY_RRULE}"
  echo "status:       ACTIVE"
  echo "─────────────── prompt（原样传入）───────────────"
  cat "$TMP/daily"
  echo ""
}
say_weekly() {
  echo "═══════════════ 周检 automation ═══════════════"
  echo "name:         ${NODE_NAME} 质量周检-NodeQuality 对比"
  echo "scheduleType: recurring"
  echo "rrule:        ${WEEKLY_RRULE}"
  echo "status:       ACTIVE"
  echo "─────────────── prompt（原样传入）───────────────"
  cat "$TMP/weekly"
  echo ""
}

case "$MODE" in
  daily)  say_daily ;;
  weekly) say_weekly ;;
  *)      say_daily; say_weekly ;;
esac

echo "提示：照上面 name/rrule/prompt 建 automation；建完手工跑一次脚本确认不报错。"
