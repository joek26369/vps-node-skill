#!/bin/bash
# ============================================================================
# 裸 IP 快查（购买前第一眼，无需任何凭据、无需配置到任何地方）
#
# 用法:
#   bash ip-check-lite.sh <IP>
#
# 查什么（全部免注册源）:
#   ipinfo      ASN / 组织 / 城市 / 时区
#   IPLogs      代理/VPN/Tor/hosting 判定 + 每条命中的信号来源（score 0-100）
#   Scamalytics Fraud Score 0-100 + 风险等级
#
# 定位: 三源快筛，明显脏的直接淘汰，不浪费购买；过了再花凭据跑 ip-audit.sh
#       完整体检（五/六节解锁与黑名单只有经代理实跑才有）。
#
# 退出码: 0 干净（可进入下一步）/ 1 可疑（人工复核）/ 2 参数错误
# ============================================================================
set -uo pipefail

IP="${1:-}"
case "$IP" in
  ''|*[!0-9.]*) echo "用法: ip-check-lite.sh <IPv4>"; exit 2 ;;
esac
OCTETS=$(printf '%s' "$IP" | awk -F. '{print NF}')
[ "$OCTETS" != "4" ] && { echo "不是合法 IPv4: $IP"; exit 2; }

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
STAMP=$(date +%Y%m%d-%H%M)
SAVEDIR="$HOME/.vps-node/ipaudits/${IP}"
mkdir -p "$SAVEDIR"
LOG="$SAVEDIR/lite-${STAMP}.log"

echo "== 裸 IP 快查: ${IP}  $(date '+%F %T') =="
{
echo "=== ipinfo ==="
curl -sS --max-time 20 "https://ipinfo.io/${IP}/json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception as e:
    print('  解析失败:', e); raise SystemExit(0)
for k in ('ip','hostname','city','region','country','org','timezone'):
    print(f'  {k}: {d.get(k)}')
" 2>&1

echo "=== IPLogs ==="
IPLOGS=$(curl -sS --max-time 20 "https://iplogs.com/api/v1/check/${IP}" 2>&1)
printf '%s\n' "$IPLOGS" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception as e:
    print('  解析失败:', e); raise SystemExit(0)
print('  score:', d.get('score'), '| verdict:', d.get('verdict'), '| reputation:', d.get('reputation'))
print('  vpn:', d.get('is_vpn'), '| proxy:', d.get('is_proxy'), '| tor:', d.get('is_tor'), '| hosting:', d.get('is_hosting'))
ii=d.get('ip_info') or {}
print('  type:', ii.get('type'), '| asn:', ii.get('asn'), ii.get('org'))
for s in (d.get('signals') or []):
    print('  signal:', s.get('type'), '| weight:', s.get('weight'))
" 2>&1

echo "=== Scamalytics ==="
SC=$(curl -sS --max-time 25 -A "$UA" "https://scamalytics.com/ip/${IP}" 2>&1)
printf '%s\n' "$SC" | python3 -c "
import re,sys
h=sys.stdin.read()
t=re.sub(r'<[^>]+>',' ',h); t=re.sub(r'\s+',' ',t)
m=re.search(r'Fraud Score:\s*(\d+)', t)
score=int(m.group(1)) if m else None
print('  fraud_score:', score if score is not None else '?')
# 以 Fraud Score 为锚点往前取窗口（页面标题里也有 Fraud Risk 字样，不能从首个匹配点找）
verdict='?'
if m:
    win=t[max(0,m.start()-300):m.start()]
    vm=re.search(r'(Very High|High|Elevated|Medium|Low|Very Low)\s*Risk', win, re.I)
    if vm:
        verdict=vm.group(1)
    elif score is not None:
        verdict='Low' if score<=10 else ('Medium' if score<=25 else 'High')
        verdict=verdict+' (按分数推断)'
print('  verdict:', verdict)
j=t.lower().find('we consider')
print('  reason:', t[j:j+160].strip() if j>=0 else '(页面未给理由)')
" 2>&1
} 2>&1 | tee "$LOG"

# ---- 判定 ----
SC_SCORE=$(grep -oE 'fraud_score: [0-9]+' "$LOG" | grep -oE '[0-9]+' | head -1)
IL_VERDICT=$(grep -oE 'verdict: [a-z]+' "$LOG" | head -1 | awk '{print $2}')
echo "----------------------------------------"
VERDICT=0
if [ -n "${SC_SCORE:-}" ]; then
  if [ "$SC_SCORE" -gt 25 ]; then
    echo "判定: Scamalytics ${SC_SCORE} > 25，高风险，建议放弃"; VERDICT=1
  elif [ "$SC_SCORE" -ge 11 ]; then
    echo "判定: Scamalytics ${SC_SCORE} 中段，建议跑完整体检再决定"; VERDICT=1
  else
    echo "判定: Scamalytics ${SC_SCORE} 低风险"
  fi
fi
[ "${IL_VERDICT:-}" != "clean" ] && { echo "判定: IPLogs verdict=${IL_VERDICT:-?} 非 clean，人工复核"; VERDICT=1; }
[ "$VERDICT" -eq 0 ] && echo "判定: 快查通过 → 下一步用代理凭据跑 ip-audit.sh 完整体检"
echo "日志: $LOG"
exit "$VERDICT"
