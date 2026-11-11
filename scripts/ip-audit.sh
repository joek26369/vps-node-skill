#!/bin/bash
# ============================================================================
# IP 完整体检（xykt IP.Check.Place 六节报告：基础信息/IP类型/风险评分/风险因子/
#             流媒体及AI解锁/黑名单，含 IPQS 评分——免注册）
#
# 原理: 该脚本测的是"测试服务器实际看到的出口 IP"，所以只要让流量从目标 IP
#       出去即可，不需要把 IP 配置到任何机器上。
#
# 用法:
#   购买后情况一（代理型 IP，有 socks5/http 凭据，IP 未配进任何机器）:
#     bash ip-audit.sh --proxy 'socks5h://user:pass@host:port' --expect <期望出口IP> [--node <别名>|--local]
#
#   购买后情况二（纯 VPS，有 SSH，直接在那台机器上跑）:
#     bash ip-audit.sh --vps-ip <IP> --vps-port <SSH端口> [--expect <该机公网IP>]
#
#   便捷模式（IP 已配进本 skill 部署的 VPS 出站 webshare-us / webshare-us2）:
#     bash ip-audit.sh --node <别名> --egress us1|us2
#
# 选项:
#   --proxy <URI>   代理地址（socks5h:// 或 http://，凭据含特殊字符会自动转义）
#   --expect <IP>   出口 echo 校验，不匹配即中止（防测错对象）
#   --vps-ip/-port  情况二: 目标 VPS 的 SSH 地址（私钥走 skill 统一探测链）
#   --node <别名>   读 ~/.vps-node/<别名>.json 定位 VPS；凭据从 VPS 上
#                   /etc/sing-box/config.json 的出站取，不落本地明文
#   --egress <tag>  便捷模式: us1|us2（对应 config.json 里的 webshare-us / webshare-us2）
#   --local         在本机跑（不推荐: 本机 Clash TUN fake-ip 会让 DNSBL 一节失真）
#
# 产出: ~/.vps-node/ipaudits/<出口IP>/<时间戳>.log（含公开报告链接）
# 退出码: 0 完成 / 3 出口校验失败 / 2 参数错误
#
# 注意: SSH 类操作请在前台运行；后台任务会被沙箱拦截 ~/.ssh 读取。
# ============================================================================
set -uo pipefail

PROXY_URI=""; EXPECT=""; NODE=""; EGRESS=""; RUN_LOCAL=0; VPS_IP=""; VPS_PORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --proxy)   PROXY_URI="${2:?need proxy uri}"; shift 2 ;;
    --expect)  EXPECT="${2:?need ip}"; shift 2 ;;
    --node)    NODE="${2:?need alias}"; shift 2 ;;
    --egress)  EGRESS="${2:?need tag like us1}"; shift 2 ;;
    --vps-ip)  VPS_IP="${2:?need ip}"; shift 2 ;;
    --vps-port) VPS_PORT="${2:?need port}"; shift 2 ;;
    --local)   RUN_LOCAL=1; shift ;;
    *)         echo "未知参数: $1"; exit 2 ;;
  esac
done

MODE_N=0
[ -n "$PROXY_URI" ] && MODE_N=$((MODE_N+1))
[ -n "$EGRESS" ] && MODE_N=$((MODE_N+1))
[ -n "$VPS_IP" ] && MODE_N=$((MODE_N+1))
if [ "$MODE_N" -ne 1 ]; then
  echo "用法（三选一）:" >&2
  echo "  ip-audit.sh --proxy <URI> --expect <IP> [--node <别名>|--local]   # 情况一: 代理型 IP" >&2
  echo "  ip-audit.sh --vps-ip <IP> --vps-port <SSH端口> [--expect <IP>]    # 情况二: 纯 VPS 直跑" >&2
  echo "  ip-audit.sh --node <别名> --egress us1|us2                        # 便捷: 已配进出站" >&2
  exit 2
fi
if [ -n "$EGRESS" ] && [ -z "$NODE" ]; then
  echo "--egress 需要 --node <别名>（凭据从该 VPS 的 config.json 取）"; exit 2
fi
# 只有代理凭据、没有指定在哪跑时，降级到本机执行（购买前通常还没有可用 VPS）
if [ -n "$PROXY_URI" ] && [ "$RUN_LOCAL" -eq 0 ] && [ -z "$NODE" ] && [ -z "$VPS_IP" ]; then
  echo "提示: 未指定 --node/--vps-ip，改在本机执行（DNSBL 一节可能因本机代理失真）" >&2
  RUN_LOCAL=1
fi
# egress 别名 -> config.json 出站 tag: us1 -> webshare-us, us2 -> webshare-us2
CTAG=""
case "$EGRESS" in
  us1) CTAG="us" ;;
  us2) CTAG="us2" ;;
  "")  ;;
  *)   echo "不认识的 --egress: ${EGRESS}（支持 us1|us2）"; exit 2 ;;
esac

# ---- SSH 定位（沿用 skill 统一密钥探测链）----
SSH_PORT=""; SSH_HOST=""
if [ "$RUN_LOCAL" -eq 0 ]; then
  if [ -n "$VPS_IP" ]; then
    SSH_HOST="$VPS_IP"
    SSH_PORT="${VPS_PORT:-22}"
  elif [ -n "$NODE" ]; then
    CRED="$HOME/.vps-node/${NODE}.json"
    [ -f "$CRED" ] || { echo "找不到 $CRED"; exit 2; }
    SSH_HOST=$(python3 -c "import json;d=json.load(open('$CRED'));print(d.get('ip') or d.get('fqdn',''))")
    SSH_PORT=$(python3 -c "import json;d=json.load(open('$CRED'));print(d.get('ssh_port','22'))")
  else
    echo "需要 --node <别名> 或 --vps-ip（或用 --local 在本机跑）"; exit 2
  fi
  [ -n "$SSH_HOST" ] || { echo "解析不到 SSH 地址"; exit 2; }
fi

KEY="${SSH_KEY:-}"
if [ "$RUN_LOCAL" -eq 0 ]; then
  if [ -z "$KEY" ]; then
    for k in "$HOME/.ssh/id_ed25519_${NODE}" "$HOME/.ssh/id_ed25519_vps" \
             "$HOME"/.ssh/id_ed25519_* "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
      [ -f "$k" ] || continue
      case "$k" in *.pub) continue ;; esac
      KEY="$k"; break
    done
  fi
  [ -n "$KEY" ] || { echo "找不到 SSH 私钥"; exit 2; }
fi

STAMP=$(date +%Y%m%d-%H%M)
TMPLOG=$(mktemp /tmp/ipaudit.XXXXXX)
trap 'rm -f "$TMPLOG"' EXIT

# ---- 远端脚本（凭据只在 VPS 侧解析，不落本地明文）----
cat > "$TMPLOG.remote" <<'REMOTE'
#!/bin/bash
set -u
PROXY_URI="$1"; EXPECT="$2"; TAG="$3"
# curl 的协议专属变量(http_proxy/https_proxy)优先级高于 ALL_PROXY，
# 环境里若已存在会被劫持，所以两者一起覆盖。
set_proxy() {
  export ALL_PROXY="$1" all_proxy="$1"
  export HTTP_PROXY="$1" http_proxy="$1"
  export HTTPS_PROXY="$1" https_proxy="$1"
}
if [ -n "$PROXY_URI" ]; then
  set_proxy "$PROXY_URI"
elif [ -n "$TAG" ]; then
  PROXY_URI=$(python3 - "$TAG" <<'PY'
import json,sys,urllib.parse
tag=sys.argv[1]
d=json.load(open('/etc/sing-box/config.json'))
for o in d['outbounds']:
    if o.get('tag')=='webshare-'+tag:
        u=urllib.parse.quote(o.get('uuid') or o.get('username') or '',safe='')
        p=urllib.parse.quote(o.get('password') or '',safe='')
        print(f"socks5h://{u}:{p}@{o['server']}:{o['server_port']}")
        break
PY
)
  [ -n "$PROXY_URI" ] || { echo "FATAL: config.json 里没有 tag=webshare-${TAG} 的出站"; exit 9; }
  set_proxy "$PROXY_URI"
fi
echo "== 出口确认 =="
EIP=$(curl -s --max-time 15 https://ipv4.webshare.io/ 2>/dev/null || true)
echo "echo_ip=${EIP:-FAIL}"
if [ -n "$EXPECT" ] && [ "$EIP" != "$EXPECT" ]; then
  echo "FATAL: 出口 ${EIP:-FAIL} != 期望 ${EXPECT}，中止体检"; exit 9
fi
echo "== 开始体检 $(date -u '+%FT%TZ') =="
curl -sL https://IP.Check.Place | bash -s 2>&1
echo "== 体检结束 $(date -u '+%FT%TZ') =="
REMOTE

# ---- 执行 ----
if [ "$RUN_LOCAL" -eq 1 ]; then
  bash "$TMPLOG.remote" "$PROXY_URI" "$EXPECT" "$CTAG" 2>&1 | tee "$TMPLOG"
  RC=${PIPESTATUS[0]}
else
  echo "跑在 ${NODE:-${SSH_HOST}}（${SSH_HOST}:${SSH_PORT}），私钥 $KEY"
  ssh -i "$KEY" -p "$SSH_PORT" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=15 "root@${SSH_HOST}" \
      "bash -s -- '${PROXY_URI}' '${EXPECT}' '${CTAG}'" < "$TMPLOG.remote" 2>&1 | tee "$TMPLOG"
  RC=${PIPESTATUS[0]}
fi

[ "$RC" -eq 9 ] && { echo "出口校验失败，未产出报告"; exit 3; }

# ---- 归档: 用实测出口 IP 命名目录 ----
EIP=$(grep -m1 '^echo_ip=' "$TMPLOG" | cut -d= -f2)
if [ -n "$EIP" ] && [ "$EIP" != "FAIL" ]; then
  SAVEDIR="$HOME/.vps-node/ipaudits/${EIP}"
  mkdir -p "$SAVEDIR"
  FINAL="$SAVEDIR/audit-${STAMP}.log"
  mv "$TMPLOG" "$FINAL"
  trap - EXIT
  echo "----------------------------------------"
  echo "日志: $FINAL"
  grep -m1 -oE 'https://Report\.Check\.Place/ip/[A-Za-z0-9]+\.svg' "$FINAL" | sed 's/^/公开报告: /' || true
  # 摘要: 六节关键行（去 ANSI）
  echo "===== 摘要 ====="
  perl -pe 's/\e\[[0-9;]*[A-Za-z]//g; s/\e\][^\e]*(\e\\|\x07)//g; s/[\x00-\x08\x0b\x0c\x0e-\x1f]//g' "$FINAL" \
    | grep -E '^(自治系统号|组织|时区|IP类型|IPQS|Scamalytics|AbuseIPDB|ipapi|IP2Location|黑名单|echo_ip=)' | head -20
fi
exit 0
