#!/bin/bash
# ============================================================================
# 节点哨兵（在 Mac 上运行，只读，流量极小）— 供每日 automation 调用
# 用法: bash vps-sentinel.sh <VPS_IP | creds.json> [--json] [--risk]
#   默认   : 服务端存活 + 双协议延迟 + 出口 IP + 证书剩余天数
#   --risk : 额外做 IP 风险复检（proxycheck + Scamalytics Fraud Score）
#   --json : 机读输出（automation 判断用），与人类输出二选一
# 退出码: 0 正常 / 1 警告 / 2 严重（出口 IP 变更或服务端不可达）
# ============================================================================
set -uo pipefail
ARG="${1:?用法: vps-sentinel.sh <VPS_IP | creds.json> [--json] [--risk]}"
JSONOUT=0; DORISK=0
for a in "$@"; do
  [ "$a" = "--json" ] && JSONOUT=1
  [ "$a" = "--risk" ] && DORISK=1
done

ok(){ [ "$JSONOUT" = "1" ] || echo "  ✅ $*"; }
warn(){ [ "$JSONOUT" = "1" ] || echo "  ⚠️  $*"; }
bad(){ [ "$JSONOUT" = "1" ] || echo "  🔴 $*"; }
note(){ [ "$JSONOUT" = "1" ] || echo "  $*"; }

# ---- 解析凭据 ----
CREDS=""
if [ -f "$ARG" ]; then CREDS="$ARG"
elif [ -f "$HOME/.vps-node/$ARG.json" ]; then CREDS="$HOME/.vps-node/$ARG.json"
else
  for f in "$HOME"/.vps-node/*.json; do
    [ -f "$f" ] || continue
    grep -q "\"ip\": *\"$ARG\"" "$f" && { CREDS="$f"; break; }
  done
fi
J(){ python3 -c "import json;print(json.load(open('$CREDS')).get('$1',''))" 2>/dev/null; }
if [ -n "$CREDS" ]; then
  IP=$(J ip); FQDN=$(J fqdn); SUBURL=$(J sub_url); DEST=$(J dest)
else
  IP="$ARG"; FQDN=""; SUBURL=""; DEST=""
fi
[ -n "$IP" ] || { echo "无法确定 IP"; exit 2; }
# 经节点期望的出口 IP：挂了住宅上游（如 Webshare）时凭据里会有 egress_ip，否则就是 VPS 本机 IP
EGRESS_EXPECTED="$IP"
[ -n "$CREDS" ] && EGRESS_EXPECTED=$(J egress_ip)
[ -n "$EGRESS_EXPECTED" ] || EGRESS_EXPECTED="$IP"
ALIAS=$(basename "${CREDS:-$IP}" .json)
NAME="${FQDN:-$IP}"
PORT="${SSH_PORT:-}"
[ -n "$CREDS" ] && [ -z "$PORT" ] && PORT=$(J ssh_port)

# ---- SSH 密钥自动探测：统一约定键 → 别名键 → 泛化 → 通用默认 ----
for k in "$HOME/.ssh/id_ed25519_vps" "$HOME/.ssh/id_ed25519_${ALIAS:-}" \
         "$HOME/.ssh/id_ed25519_${FQDN%%.*}" "$HOME"/.ssh/id_ed25519_* \
         "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
  [ -f "$k" ] || continue
  case "$k" in *.pub) continue ;; esac
  KEYARG=(-i "$k"); break
done
# 保证数组非空，避免 bash 3.2 + set -u 下展开报 unbound
[ ${#KEYARG[@]} -eq 0 ] && KEYARG=()
SSHOPT=("${KEYARG[@]}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=15 -o BatchMode=yes -o LogLevel=ERROR)

# 端口：凭据里没有就试 22 / 2222
try_port(){
  for p in ${PORT:-} 22 2222; do
    [ -z "$p" ] && continue
    if ssh "${SSHOPT[@]}" -p "$p" "root@$IP" 'echo OK' 2>/dev/null | grep -q OK; then
      echo "$p"; return 0
    fi
  done
  return 1
}
RPORT=$(try_port || true)

# ---- 1. 服务端存活 ----
SB="down"; HOSTUP=0
if [ -n "$RPORT" ]; then
  HOSTUP=1
  SB=$(ssh "${SSHOPT[@]}" -p "$RPORT" "root@$IP" \
       'systemctl is-active sing-box 2>/dev/null; ss -tln 2>/dev/null | grep -c ":443 "' 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
fi

# ---- 2. 本机 mihomo 延迟 ----
SOCK=""
for s in /var/run/clash-verge-service/users/"$(id -u)"/verge-mihomo.sock \
         "$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge-mihomo.sock"; do
  [ -S "$s" ] && { SOCK="$s"; break; }
done
SECRET=""
for cfg in "$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/"*.yaml; do
  [ -f "$cfg" ] || continue
  s=$(grep -E '^[[:space:]]*secret:' "$cfg" 2>/dev/null | head -1 | sed 's/.*secret:[[:space:]]*//' | tr -d "\"'")
  [ -n "$s" ] && { SECRET="$s"; break; }
done

DELAY_REALITY=""; DELAY_HY2=""
if [ -n "$SOCK" ]; then
  MI=(-s --unix-socket "$SOCK")
  [ -n "$SECRET" ] && MI+=(-H "Authorization: Bearer $SECRET")
  NAMES=$(curl "${MI[@]}" --max-time 8 http://localhost/proxies 2>/dev/null \
    | python3 -c "
import json,sys
try: d=json.load(sys.stdin).get('proxies',{})
except: raise SystemExit
for k in d:
    if 'REALITY' in k: print('R '+k)
    elif 'Hy2' in k or 'HY2' in k or 'hysteria' in k.lower(): print('H '+k)" 2>/dev/null)
  while IFS=' ' read -r tag nm; do
    [ -z "${nm:-}" ] && continue
    ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$nm")
    D=$(curl "${MI[@]}" --max-time 12 -G --data-urlencode "timeout=8000" \
        --data-urlencode "url=https://www.gstatic.com/generate_204" \
        "http://localhost/proxies/${ENC}/delay" 2>/dev/null \
        | python3 -c "import json,sys;print(json.load(sys.stdin).get('delay',''))" 2>/dev/null)
    if [ "$tag" = "R" ]; then DELAY_REALITY="$D"; else DELAY_HY2="$D"; fi
  done <<< "$NAMES"
fi

# ---- 3. 出口 IP ----
PX=""
for p in 7897 7890 7891 1087; do nc -z -G 1 127.0.0.1 "$p" 2>/dev/null && { PX="http://127.0.0.1:$p"; break; }; done
EGRESS=""
[ -n "$PX" ] && EGRESS=$(curl -s --noproxy '*' -m 12 -x "$PX" https://api.ip.sb/ip 2>/dev/null | tr -d '\n')

# ---- 4. 证书剩余天数 ----
CERTDAYS=""
if [ -n "$SUBURL" ]; then
  H=$(echo "$SUBURL" | sed -E 's#https://([^:/]+).*#\1#')
  EXP=$(echo | perl -e 'alarm 10; exec @ARGV' openssl s_client -connect "$H:2096" -servername "$H" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
  if [ -n "$EXP" ]; then
    ETS=$(date -j -f "%b %e %H:%M:%S %Y %Z" "$EXP" +%s 2>/dev/null || echo "")
    [ -n "$ETS" ] && CERTDAYS=$(( (ETS - $(date +%s)) / 86400 ))
  fi
fi

# ---- 5. 风险复检（可选）----
RISK=""; FRAUD=""
if [ "$DORISK" = "1" ]; then
  RISK=$(curl -s --noproxy '*' -m 12 "https://proxycheck.io/v2/$IP?vpn=1&risk=1" 2>/dev/null \
         | python3 -c "
import json,sys
try:
    d=list(json.load(sys.stdin).values())[1]
    print(f\"proxy={d.get('proxy')} risk={d.get('risk')}\")
except: print('')" 2>/dev/null)
  CPXOPT=""; [ -n "$PX" ] && CPXOPT="-x $PX"
  FRAUD=$(curl -s --noproxy '*' -m 20 $CPXOPT -A "Mozilla/5.0" "https://scamalytics.com/ip/$IP" 2>/dev/null \
          | python3 -c "
import sys,re
h=sys.stdin.read()
m=re.search(r'Fraud Score:\s*(\d+)',h)
print(m.group(1) if m else '')" 2>/dev/null)
fi

# ---- 判定 ----
LVL=0   # 0 ok / 1 warn / 2 critical
ISSUES=()
SB_ST="${SB%% *}"          # 第一段：active / inactive / failed
SB_443="${SB##* }"         # 第二段：443 监听条数

if [ "$HOSTUP" != "1" ]; then
  LVL=2; ISSUES+=("SSH 不可达")
else
  case "$SB_ST" in
    active) ;;
    *) LVL=2; ISSUES+=("sing-box 未运行(${SB_ST:-未知})") ;;
  esac
  [ "$SB_443" = "1" ] || { [ "$LVL" -lt 2 ] && LVL=1; ISSUES+=("443 监听异常(${SB_443:-0})"); }
fi

if [ -n "$DELAY_REALITY" ]; then
  [ "$DELAY_REALITY" -gt 400 ] 2>/dev/null && { [ "$LVL" -lt 1 ] && LVL=1; ISSUES+=("REALITY ${DELAY_REALITY}ms 偏高"); }
else
  [ -n "$SOCK" ] && { [ "$LVL" -lt 1 ] && LVL=1; ISSUES+=("REALITY 探测失败"); }
fi
if [ -n "$DELAY_HY2" ]; then
  [ "$DELAY_HY2" -gt 400 ] 2>/dev/null && { [ "$LVL" -lt 1 ] && LVL=1; ISSUES+=("Hy2 ${DELAY_HY2}ms 偏高"); }
fi
# egress_ip 支持逗号分隔多出口（双 Webshare 主备时两个都是合法出口）
EGRESS_OK=0
case ",$EGRESS_EXPECTED," in
  *",$EGRESS,"*) EGRESS_OK=1 ;;
esac
if [ -n "$EGRESS" ] && [ "$EGRESS_OK" = "0" ]; then
  LVL=2; ISSUES+=("出口 IP 变为 ${EGRESS}（应为 ${EGRESS_EXPECTED}）")
fi
if [ -n "$CERTDAYS" ] && [ "$CERTDAYS" -lt 14 ] 2>/dev/null; then
  [ "$LVL" -lt 1 ] && LVL=1; ISSUES+=("证书仅剩 ${CERTDAYS} 天")
fi

# ---- 输出 ----
if [ "$JSONOUT" = "1" ]; then
  printf '{"name":"%s","ip":"%s","ssh_port":"%s","level":%s,"singbox":"%s","delay_reality":"%s","delay_hy2":"%s","egress":"%s","cert_days":"%s","risk":"%s","fraud":"%s","issues":[' \
    "$NAME" "$IP" "${RPORT:-}" "$LVL" "${SB% *}" "$DELAY_REALITY" "$DELAY_HY2" "$EGRESS" "$CERTDAYS" "$RISK" "$FRAUD"
  first=1
  for i in "${ISSUES[@]:-}"; do
    [ -z "$i" ] && continue
    [ "$first" = "1" ] || printf ','
    printf '"%s"' "$i"; first=0
  done
  printf ']}\n'
else
  case "$LVL" in
    0) echo "✅ ${NAME} 正常 | REALITY ${DELAY_REALITY:-—}ms · Hy2 ${DELAY_HY2:-—}ms | 出口 ${EGRESS:-—} | 证书 ${CERTDAYS:-—}天" ;;
    1) echo "⚠️  ${NAME} 需要关注: ${ISSUES[*]}" ;;
    2) echo "🔴 ${NAME} 严重: ${ISSUES[*]}" ;;
  esac
  echo ""
  note "服务端 : ${SB:-未知}  (SSH 端口 ${RPORT:-不可达})"
  note "延迟   : REALITY ${DELAY_REALITY:-—}ms · Hy2 ${DELAY_HY2:-—}ms"
  note "出口   : ${EGRESS:-查询失败}（预期 ${EGRESS_EXPECTED}）"
  note "证书   : ${CERTDAYS:-—} 天后到期"
  [ "$DORISK" = "1" ] && note "风险   : ${RISK:-查询失败} · Fraud Score ${FRAUD:-—}"
fi
exit "$LVL"
