#!/bin/bash
# ============================================================================
# 节点验收（在 Mac 上运行，Verge 激活前后都可跑）
# 用法: bash vps-verify.sh <VPS_IP | 凭据JSON路径> [--browser]
# 检查: TCP 443 可达 / REALITY 借壳证书 / HTTPS 订阅有效性 /
#       mihomo 节点延迟（需 Verge 已激活卡片）/ 出口 IP / 可选浏览器直连
# ============================================================================
set -uo pipefail
ARG="${1:?用法: vps-verify.sh <VPS_IP | creds.json> [--browser]}"
DO_BROWSER=0
for a in "$@"; do [ "$a" = "--browser" ] && DO_BROWSER=1; done

ok(){ echo "  ✅ $*"; }
bad(){ echo "  ❌ $*"; }
warn(){ echo "  ⚠️  $*"; }

# ---- 解析凭据 ----
CREDS=""
if [ -f "$ARG" ]; then CREDS="$ARG"
elif [ -f "$HOME/.vps-node/$ARG.json" ]; then CREDS="$HOME/.vps-node/$ARG.json"
else
  # 按 IP 在凭据目录里匹配
  for f in "$HOME"/.vps-node/*.json; do
    [ -f "$f" ] || continue
    grep -q "\"ip\": *\"$ARG\"" "$f" && { CREDS="$f"; break; }
  done
fi

if [ -n "$CREDS" ]; then
  IP=$(python3 -c "import json,sys;print(json.load(open('$CREDS')).get('ip',''))" 2>/dev/null)
  FQDN=$(python3 -c "import json,sys;print(json.load(open('$CREDS')).get('fqdn',''))" 2>/dev/null)
  SUBURL=$(python3 -c "import json,sys;print(json.load(open('$CREDS')).get('sub_url',''))" 2>/dev/null)
  DEST=$(python3 -c "import json,sys;print(json.load(open('$CREDS')).get('dest',''))" 2>/dev/null)
else
  IP="$ARG"; FQDN=""; SUBURL=""; DEST=""
fi
[ -n "$IP" ] || { echo "无法确定 IP"; exit 1; }
echo "=============== 节点验收: $IP ==============="
echo ""

# ---- 1. TCP 443 可达 ----
echo "--- 1. TCP 443 可达性 ---"
if nc -z -G 5 "$IP" 443 2>/dev/null; then ok "443/tcp 可连接"
else bad "443/tcp 不可达（ufw 未放行 或 sing-box 未运行）"; fi
echo ""

# ---- 2. REALITY 借壳证书 ----
echo "--- 2. REALITY 借壳真实性（应返回 dest 站点的真实证书）---"
SNI="${DEST:-www.paypal.com}"
CERT=$(echo | perl -e 'alarm 15; exec @ARGV' openssl s_client -connect "$IP:443" -servername "$SNI" 2>/dev/null \
       | openssl x509 -noout -subject -issuer 2>/dev/null | tr '\n' ' ')
if [ -n "$CERT" ]; then
  echo "  SNI=$SNI"
  echo "  $CERT" | sed 's/^/  /'
  if echo "$CERT" | grep -qiE 'paypal|bing|microsoft|apple|cloudflare|digicert|let'"'"'s encrypt'; then
    ok "证书链正常，REALITY 借壳生效"
  else
    warn "证书异常，请确认 dest 站点是否支持 TLS1.3 + H2"
  fi
else
  bad "TLS 握手失败（dest=${SNI}，可能被 ufw 拦或 REALITY 配置错误）"
fi
echo ""

# ---- 3. HTTPS 订阅 ----
echo "--- 3. HTTPS 订阅端点 ---"
if [ -n "$SUBURL" ]; then
  CODE=$(curl -s --max-time 15 -o /tmp/vpsverify_sub.yaml -w "%{http_code}" "$SUBURL" 2>/dev/null || echo 000)
  if [ "$CODE" = "200" ] && grep -q '^proxies:' /tmp/vpsverify_sub.yaml 2>/dev/null; then
    N=$(grep -c '^  - name:' /tmp/vpsverify_sub.yaml)
    HOST=$(echo "$SUBURL" | sed -E 's#https://([^:/]+).*#\1#')
    EXP=$(echo | perl -e 'alarm 10; exec @ARGV' openssl s_client -connect "$HOST:2096" 2>/dev/null \
          | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    ok "HTTP 200，节点数 $N"
    [ -n "$EXP" ] && echo "     证书到期: $EXP"
  else
    bad "订阅拉取失败 HTTP ${CODE}（证书未签发 / 服务未启动 / ufw 未放行 2096）"
  fi
  rm -f /tmp/vpsverify_sub.yaml
else
  warn "未提供订阅 URL，跳过（可手动 curl）"
fi
echo ""

# ---- 4. mihomo 节点延迟 ----
echo "--- 4. Clash Verge 节点延迟（需已点击卡片激活）---"
SOCK=""
for s in /var/run/clash-verge-service/users/"$(id -u)"/verge-mihomo.sock \
         "$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge-mihomo.sock"; do
  [ -S "$s" ] && { SOCK="$s"; break; }
done
if [ -z "$SOCK" ]; then
  warn "未找到 mihomo 控制 socket，跳过（在 Verge 界面手动看延迟）"
else
  SECRET=""
  for cfg in "$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/"*.yaml; do
    [ -f "$cfg" ] || continue
    s=$(grep -E '^[[:space:]]*secret:' "$cfg" 2>/dev/null | head -1 | sed 's/.*secret:[[:space:]]*//' | tr -d "\"'")
    [ -n "$s" ] && { SECRET="$s"; break; }
  done
  MI=(-s --unix-socket "$SOCK")
  [ -n "$SECRET" ] && MI+=(-H "Authorization: Bearer $SECRET")
  NAMES=$(curl "${MI[@]}" --max-time 8 http://localhost/proxies 2>/dev/null \
          | python3 -c "
import json,sys
try: d=json.load(sys.stdin).get('proxies',{})
except: raise SystemExit
print('\n'.join(k for k in d if 'REALITY' in k or 'Hy2' in k or 'VPS-' in k))" 2>/dev/null)
  if [ -z "$NAMES" ]; then
    warn "控制接口可连但未发现本节点（卡片可能还没激活，或订阅未加载）"
  else
    while IFS= read -r n; do
      [ -z "$n" ] && continue
      D=$(curl "${MI[@]}" --max-time 12 -G \
          --data-urlencode "timeout=5000" --data-urlencode "url=http://www.gstatic.com/generate_204" \
          "http://localhost/proxies/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$n")/delay" 2>/dev/null \
          | python3 -c "import json,sys;print(json.load(sys.stdin).get('delay','-'))" 2>/dev/null)
      if [ "$D" = "-" ] || [ -z "$D" ]; then bad "$n 延迟测试失败"; else ok "$n 延迟 ${D}ms"; fi
    done <<< "$NAMES"
  fi
fi
echo ""

# ---- 5. 出口 IP（经 Clash 代理）----
echo "--- 5. 出口 IP（经本机 Clash 代理）---"
# 挂了住宅上游时凭据里会有 egress_ip（经节点应看到的出口），否则以 VPS IP 为准
EXPECTED_EGRESS="$IP"
[ -n "$CREDS" ] && EXPECTED_EGRESS=$(python3 -c "import json;print(json.load(open('$CREDS')).get('egress_ip') or '$IP')" 2>/dev/null)
[ -n "$EXPECTED_EGRESS" ] || EXPECTED_EGRESS="$IP"
PX=""
for p in 7897 7890 7891 1087; do nc -z -G 1 127.0.0.1 "$p" 2>/dev/null && { PX="http://127.0.0.1:$p"; break; }; done
if [ -z "$PX" ]; then
  warn "未探测到 Clash HTTP 端口，跳过"
else
  EGRESS=$(curl -s --max-time 12 -x "$PX" https://api.ip.sb/ip 2>/dev/null | tr -d '\n')
  # egress_ip 支持逗号分隔多出口（双 Webshare 主备）
  EGRESS_OK=0
  case ",$EXPECTED_EGRESS," in
    *",$EGRESS,"*) EGRESS_OK=1 ;;
  esac
  if [ "$EGRESS_OK" = "1" ]; then ok "出口 = ${EGRESS}（与预期一致）"
  elif [ -n "$EGRESS" ]; then warn "出口 = ${EGRESS}（预期 ${EXPECTED_EGRESS}，当前选中的可能不是本节点）"
  else warn "出口查询失败"; fi
fi
echo ""

# ---- 6. 浏览器直连（可选）----
if [ "$DO_BROWSER" = "1" ]; then
  echo "--- 6. 真实浏览器直连（需 Clash 已切到本节点 + TUN/系统代理开启）---"
  CHROME=""
  for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
           "/Applications/Chromium.app/Contents/MacOS/Chromium" \
           "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"; do
    [ -x "$c" ] && { CHROME="$c"; break; }
  done
  if [ -z "$CHROME" ]; then
    warn "未找到 Chrome/Chromium，跳过"
  else
    for site in claude.ai chatgpt.com; do
      CDIR=$(mktemp -d /tmp/chrome-verify.XXXXXX)
      DOM=$(mktemp /tmp/vb.XXXXXX)   # BSD mktemp 要求模板以 X 结尾
      "$CHROME" --headless=new --disable-gpu --user-data-dir="$CDIR" \
        ${PX:+--proxy-server="$PX"} --virtual-time-budget=18000 --timeout=35000 \
        --dump-dom "https://$site" 2>/dev/null > "$DOM"
      rm -rf "$CDIR"
      HIT=$(python3 - "$DOM" "$site" <<'PY'
import sys,re
h=open(sys.argv[1],encoding='utf-8',errors='ignore').read().lower()
site=sys.argv[2]
sig = ['log in','sign in','登录','continue','chat','new chat','conversation'] if site=='chatgpt.com' else ['claude','log in','sign in','continue','chat']
if 'cloudflare' in h and 'challenge' in h: print('BLOCKED:cf-challenge')
elif 'access denied' in h or 'unusual traffic' in h: print('BLOCKED:denied')
elif any(s in h for s in sig): print('OK')
else: print('UNKNOWN')
PY
)
      case "$HIT" in
        OK) ok "$site 直连正常（出现对话/登录界面）";;
        BLOCKED*) bad "$site 被拦（${HIT#BLOCKED:}）";;
        *) warn "$site 结果不明确，建议人工打开确认";;
      esac
      rm -f "$DOM"
    done
  fi
  echo ""
fi

echo "=============== 验收结束 ==============="
echo "未覆盖项: Hysteria2 UDP 8443（UDP 无法可靠自动探测，靠实际连通判断）"
