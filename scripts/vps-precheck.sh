#!/bin/bash
# ============================================================================
# VPS 预检（部署之前跑）— 判断这台机器和这个 IP 值不值得留下
#
# 用法:
#   bash vps-precheck.sh <IP> <SSH端口> <root密码>
#   bash vps-precheck.sh <IP> <SSH端口> --key ~/.ssh/id_ed25519_xxx
#   bash vps-precheck.sh <IP> <SSH端口> '<密码>' --ipaudit    # 再加 9 项外部 IP 体检
#   bash vps-precheck.sh <IP> <SSH端口> --key ~/.ssh/xxx --deep  # 再加 NodeQuality 深度报告
#   TARGET=<你家宽出口IP> bash vps-precheck.sh ...      # 回程目标改成自家家宽
#
# 环境变量:
#   TARGET=114.114.114.114   回程探测目标
#   SKIP_SPEED=1             跳过 20MB 带宽实测
#   SKIP_NET_IO=1            跳过磁盘 IO 与带宽测试（最省流量/IO）
#   FORCE=1                  即使 FAIL 也返回 0（供编排器强制继续）
#
# 退出码: 0 通过 / 1 有警告但可部署 / 2 不建议部署
# ============================================================================
set -uo pipefail

IP="${1:?用法: vps-precheck.sh <IP> <SSH端口> <root密码|--key 路径>}"
PORT="${2:?need ssh port}"
shift 2

PASS=""; KEY=""; DO_IPAUDIT="${IPAUDIT:-0}"; DO_DEEP="${DEEP:-0}"
while [ $# -gt 0 ]; do
  case "$1" in
    --key|-i)  KEY="${2:?need key path}"; shift 2 ;;
    --ipaudit) DO_IPAUDIT=1; shift ;;
    --deep)    DO_DEEP=1; shift ;;
    --all)     DO_IPAUDIT=1; DO_DEEP=1; shift ;;
    -*)        echo "未知参数: $1"; exit 2 ;;
    *)         [ -z "$PASS" ] && PASS="$1"; shift ;;
  esac
done
[ -z "$PASS" ] && [ -z "$KEY" ] && PASS="${SSH_PASS:-}"
if [ -z "$PASS" ] && [ -z "$KEY" ]; then
  echo "缺少 root 密码（或 --key <私钥路径>）"; exit 2
fi

TARGET="${TARGET:-114.114.114.114}"
SKIP_SPEED="${SKIP_SPEED:-0}"
SKIP_NET_IO="${SKIP_NET_IO:-0}"
FORCE="${FORCE:-0}"

HERE="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d /tmp/vpspx.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- SSH 传输层
if [ -n "$KEY" ]; then
  SSHBASE="-i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
  ssh_run() { ssh $SSHBASE -o ConnectTimeout=15 -o BatchMode=yes -p "$PORT" "root@$IP" "$@" 2>&1 | grep -vE '^Warning: Permanently'; }
  scp_run() { scp $SSHBASE -P "$PORT" "$1" "root@$IP:$2"; }
else
  if ! command -v expect >/dev/null 2>&1; then
    echo "缺少 expect（macOS: brew install expect），或改用 --key 走密钥登录"; exit 2
  fi
  cat > "$TMP/sshx.exp" <<'EXP'
#!/usr/bin/expect -f
set timeout 400
set port [lindex $argv 0]
set ip   [lindex $argv 1]
set cmd  [lindex $argv 2]
spawn ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o LogLevel=ERROR -p $port root@$ip $cmd
expect {
  -re "Permission denied|Authentication failed" { exit 2 }
  "password:" { send "$env(VPSPASS)\r"; exp_continue }
  eof
}
catch wait result
exit [lindex $result 3]
EXP
  cat > "$TMP/scpx.exp" <<'EXP'
#!/usr/bin/expect -f
set timeout 180
set port [lindex $argv 0]
set ip   [lindex $argv 1]
set src  [lindex $argv 2]
set dst  [lindex $argv 3]
spawn scp -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P $port $src root@$ip:$dst
expect {
  -re "Permission denied|Authentication failed" { exit 2 }
  "password:" { send "$env(VPSPASS)\r"; exp_continue }
  eof
}
catch wait result
exit [lindex $result 3]
EXP
  ssh_run() {
    VPSPASS="$PASS" expect "$TMP/sshx.exp" "$PORT" "$IP" "$*" 2>&1 \
      | tr -d '\r' | grep -vE '^(spawn |Warning: Permanently)'
  }
  scp_run() {
    VPSPASS="$PASS" expect "$TMP/scpx.exp" "$PORT" "$IP" "$1" "$2" 2>&1 \
      | tr -d '\r' | grep -vE '^(spawn |Warning: Permanently)'
  }
fi

# ---------------------------------------------------------------- 远端探测脚本
cat > "$TMP/remote.sh" <<'REMOTE'
#!/bin/bash
# 在 VPS 上执行，纯只读（除 apt 装 mtr、临时 IO 文件）
TGT="$1"
export LC_ALL=C
. /etc/os-release 2>/dev/null && echo "OS=$PRETTY_NAME"
echo "KERNEL=$(uname -r)"
echo "ARCH=$(uname -m)"
echo "CPU_MODEL=$(awk -F': *' '/^model name|^Model|^cpu model/{print $2;exit}' /proc/cpuinfo | sed 's/[[:space:]]\+/ /g')"
echo "CPU_CORE=$(nproc 2>/dev/null || echo 1)"
echo "MEM_MB=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo)"
DFLINE=$(df -Pm / 2>/dev/null | awk 'NR==2{print $2" "$4}')
echo "DISK_TOTAL_MB=$(echo "$DFLINE" | awk '{print $1}')"
echo "DISK_FREE_MB=$(echo "$DFLINE" | awk '{print $2}')"
V=$(systemd-detect-virt 2>/dev/null); echo "VIRT=${V:-none}"
if [ -d /proc/vz ] || [ -d /proc/bc ]; then echo "VIRT_OPENVZ=1"; else echo "VIRT_OPENVZ=0"; fi
echo "CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo NA)"
echo "UPTIME_H=$(awk '{printf "%d",$1/3600}' /proc/uptime)"
echo "LOAD1=$(awk '{print $1}' /proc/loadavg)"
echo "EXIST_SINGBOX=$(command -v sing-box >/dev/null 2>&1 && echo yes || echo no)"
echo "EXIST_XRAY=$(command -v xray >/dev/null 2>&1 && echo yes || echo no)"
echo "EXIST_3XUI=$(command -v x-ui >/dev/null 2>&1 && echo yes || echo no)"
echo "EXIST_NGINX=$(command -v nginx >/dev/null 2>&1 && echo yes || echo no)"
if command -v ss >/dev/null 2>&1; then
  echo "PORT_443=$(ss -lntH 2>/dev/null | awk '$4 ~ /:443$/' | wc -l | tr -d ' ')"
  echo "PORT_80=$(ss -lntH 2>/dev/null | awk '$4 ~ /:80$/' | wc -l | tr -d ' ')"
else
  echo "PORT_443=NA"; echo "PORT_80=NA"
fi
echo "NET_GITHUB=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 https://github.com 2>/dev/null || echo 000)"
echo "NET_CLOUDFLARE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://speed.cloudflare.com 2>/dev/null || echo 000)"
# 出口 IP 与归属（VPS 自己的视角）
echo "EGRESS_JSON=$(curl -s --max-time 12 'http://ip-api.com/json/?fields=status,country,regionName,city,isp,org,as,proxy,hosting' 2>/dev/null | tr -d '\n')"
# AI 站落地风控：从本机直连（不经节点），反映这个 IP 本身的信誉
# 关键：裸 curl 没有浏览器指纹，403 不代表被封；要区分「Cloudflare 挑战」与普通拒绝
UAX='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
CLH=$(curl -s -o /dev/null -D - -A "$UAX" --max-time 12 https://claude.ai 2>/dev/null)
echo "AI_CLAUDE=$(echo "$CLH" | head -1 | grep -oE '[0-9]{3}' | head -1)"
echo "AI_CLAUDE_CF=$(echo "$CLH" | grep -ci 'cf-mitigated')"
CGH=$(curl -s -o /dev/null -D - -A "$UAX" --max-time 12 https://chatgpt.com 2>/dev/null)
echo "AI_CHATGPT=$(echo "$CGH" | head -1 | grep -oE '[0-9]{3}' | head -1)"
echo "AI_CHATGPT_CF=$(echo "$CGH" | grep -ci 'cf-mitigated')"
echo "AI_ANTHROPIC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://api.anthropic.com/v1/models 2>/dev/null || echo 000)"
# 磁盘 IO
if [ "${SKIP_NET_IO:-0}" != "1" ]; then
  dd if=/dev/zero of=/tmp/.pxio bs=1M count=64 conv=fdatasync >/tmp/.pxio.log 2>&1
  IOV=$(tail -1 /tmp/.pxio.log | grep -oE '[0-9.]+ [kMG]B/s' | head -1)
  echo "DISK_IO=${IOV:-NA}"
  rm -f /tmp/.pxio /tmp/.pxio.log
else
  echo "DISK_IO=SKIPPED"
fi
# 单线程下行带宽（20MB）
if [ "${SKIP_NET_IO:-0}" != "1" ] && [ "${SKIP_SPEED:-0}" != "1" ]; then
  SP=$(curl -s -o /dev/null -w '%{speed_download}' --max-time 25 "https://speed.cloudflare.com/__down?bytes=20000000" 2>/dev/null)
  echo "SPEED_MBPS=$(echo "$SP" | awk '{printf "%.1f", $1*8/1000000}')"
else
  echo "SPEED_MBPS=SKIPPED"
fi
# 回程 AS 路径：优先 nexttrace（mtr --aslookup 对无 PTR 的跳显示 AS???，
# 会把 AS10099/AS9929 这类精品段吞掉，导致误判"没有精品线路"）
if ! command -v nexttrace >/dev/null 2>&1; then
  curl -sL --max-time 60 nxtrace.org/nt 2>/dev/null | bash >/dev/null 2>&1 || true
fi
if command -v nexttrace >/dev/null 2>&1; then
  echo "TRACE_TOOL=nexttrace"
  echo "TRACE_BEGIN"
  nexttrace -q 2 "$TGT" 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -vE '^NextTrace |^\[NextTrace API\]|^IP Geo Data Provider' \
    | grep -vE '^[[:space:]]*$' \
    | head -44
  echo "TRACE_END"
else
  if ! command -v mtr >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y mtr-tiny >/dev/null 2>&1 || true
  fi
  echo "TRACE_TOOL=mtr"
  echo "TRACE_BEGIN"
  if command -v mtr >/dev/null 2>&1; then
    mtr -rwzc 5 --aslookup -m 16 "$TGT" 2>/dev/null
  else
    echo "TRACE_UNAVAILABLE"
  fi
  echo "TRACE_END"
fi
REMOTE

# ---------------------------------------------------------------- 1. 上传并执行
echo "== 预检 $(date '+%H:%M:%S') · $IP:$PORT =="
if [ -n "$KEY" ]; then
  echo "  用密钥登录并采集机器信息（约 20-60 秒）..."
else
  echo "  用密码登录并采集机器信息（约 20-60 秒）..."
fi
scp_run "$TMP/remote.sh" "/tmp/.vps-precheck-remote.sh" >/dev/null 2>&1
UP=$?
if [ "$UP" -ne 0 ]; then
  # 密钥模式下 scp 失败通常是 key 不对或端口不通
  if ! ssh_run "test -f /tmp/.vps-precheck-remote.sh && echo EXISTS" 2>/dev/null | grep -q EXISTS; then
    echo ""
    echo "❌ 无法登录 $IP:$PORT —— 密码或密钥错误、SSH 端口不对、或机器网络不通"
    echo "   排查: nc -vz $IP $PORT"
    exit 2
  fi
fi

RAW=$(ssh_run "SKIP_NET_IO='$SKIP_NET_IO' SKIP_SPEED='$SKIP_SPEED' bash /tmp/.vps-precheck-remote.sh '$TARGET'; rm -f /tmp/.vps-precheck-remote.sh" 2>&1)
if [ -z "$RAW" ]; then
  echo ""
  echo "❌ 远端执行无输出 —— SSH 认证失败或 root 无 bash"
  exit 2
fi

g() { echo "$RAW" | grep -m1 "^$1=" | sed "s/^$1=//"; }

OS=$(g OS); KERNEL=$(g KERNEL); ARCH=$(g ARCH)
CPU_MODEL=$(g CPU_MODEL); CPU_CORE=$(g CPU_CORE)
MEM_MB=$(g MEM_MB); DISK_TOTAL_MB=$(g DISK_TOTAL_MB); DISK_FREE_MB=$(g DISK_FREE_MB)
VIRT=$(g VIRT); VIRT_OPENVZ=$(g VIRT_OPENVZ); CC=$(g CC)
UPTIME_H=$(g UPTIME_H); LOAD1=$(g LOAD1)
EXIST_SINGBOX=$(g EXIST_SINGBOX); EXIST_XRAY=$(g EXIST_XRAY)
EXIST_3XUI=$(g EXIST_3XUI); EXIST_NGINX=$(g EXIST_NGINX)
PORT_443=$(g PORT_443); PORT_80=$(g PORT_80)
NET_GITHUB=$(g NET_GITHUB); NET_CLOUDFLARE=$(g NET_CLOUDFLARE)
DISK_IO=$(g DISK_IO); SPEED_MBPS=$(g SPEED_MBPS)
EGRESS_JSON=$(g EGRESS_JSON)
AI_CLAUDE=$(g AI_CLAUDE); AI_CLAUDE_CF=$(g AI_CLAUDE_CF)
AI_CHATGPT=$(g AI_CHATGPT); AI_CHATGPT_CF=$(g AI_CHATGPT_CF)
AI_ANTHROPIC=$(g AI_ANTHROPIC)
TRACE_TOOL=$(g TRACE_TOOL); TRACE_TOOL=${TRACE_TOOL:-mtr}
TRACE_BLOCK=$(echo "$RAW" | sed -n '/^TRACE_BEGIN$/,/^TRACE_END$/p' | grep -vE '^TRACE_(BEGIN|END)$')

# ---------------------------------------------------------------- 2. 目标 IP 情报
echo "  查询 $IP 的 IP 质量（ip-api / proxycheck）..."
IPAPI=""
if command -v curl >/dev/null 2>&1; then
  IPAPI=$(curl -s --max-time 12 "http://ip-api.com/json/$IP?fields=status,country,regionName,city,isp,org,as,proxy,hosting,mobile" 2>/dev/null | tr -d '\n')
fi
PXC=""
if command -v curl >/dev/null 2>&1; then
  PXC=$(curl -s --max-time 15 "https://proxycheck.io/v2/$IP?vpn=1&asn=1&risk=1" 2>/dev/null | tr -d '\n')
fi

J() {  # J <json> <key> —— 取顶层字符串/数字
  echo "$1" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    v=d.get('$2','')
    print(v if not isinstance(v,(dict,list)) else json.dumps(v,ensure_ascii=False))
except Exception:
    print('')
" 2>/dev/null
}

IP_COUNTRY=$(J "$IPAPI" country); IP_REGION=$(J "$IPAPI" regionName); IP_CITY=$(J "$IPAPI" city)
IP_ISP=$(J "$IPAPI" isp); IP_ORG=$(J "$IPAPI" org); IP_AS=$(J "$IPAPI" as)
IP_PROXY=$(J "$IPAPI" proxy); IP_HOSTING=$(J "$IPAPI" hosting)

PXC_RISK=""; PXC_PROXY=""; PXC_TYPE=""
if [ -n "$PXC" ]; then
  PXC_RISK=$(echo "$PXC" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('$IP',{}).get('risk',''))
except Exception: print('')
" 2>/dev/null)
  PXC_PROXY=$(echo "$PXC" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('$IP',{}).get('proxy',''))
except Exception: print('')
" 2>/dev/null)
  PXC_TYPE=$(echo "$PXC" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('$IP',{}).get('type',''))
except Exception: print('')
" 2>/dev/null)
fi

# 回程 AS 摘要
RET_AS=$(echo "$TRACE_BLOCK" | grep -oE 'AS[0-9]+' | sort -u | tr '\n' ' ')
RET_BOUTIQUE=""
case "$RET_AS" in
  *AS9929*)   RET_BOUTIQUE="AS9929 联通 CUII 精品" ;;
esac
case "$RET_AS" in
  *AS4809*)   RET_BOUTIQUE="${RET_BOUTIQUE:-}${RET_BOUTIQUE:+ / }AS4809 电信 CN2" ;;
esac
case "$RET_AS" in
  *AS10099*)  RET_BOUTIQUE="${RET_BOUTIQUE:-}${RET_BOUTIQUE:+ / }AS10099 联通国际 CUG" ;;
  *AS58807*)  RET_BOUTIQUE="${RET_BOUTIQUE:-}${RET_BOUTIQUE:+ / }AS58807 移动 CMIN2" ;;
esac
if [ -z "$RET_BOUTIQUE" ] && echo "$TRACE_BLOCK" | grep -qE 'CUG|CU169|CN2|CMIN2'; then
  RET_BOUTIQUE="含精品骨干网代号"
fi

# ---------------------------------------------------------------- 2.5 可选深度检查
IPAUDIT_LOG=""; PXC_FRAUD=""; PXC_ABUSE=""; DEEP_LOG=""
if [ "$DO_IPAUDIT" = "1" ]; then
  echo ""
  echo "  追加 9 项外部 IP 体检（1-2 分钟：ipinfo / Scamalytics / AbuseIPDB / DNSBL ...）..."
  mkdir -p "$HOME/.vps-node"; chmod 700 "$HOME/.vps-node" 2>/dev/null
  IPAUDIT_LOG="$HOME/.vps-node/precheck-${IP}-ipaudit-$(date +%Y%m%d-%H%M).log"
  bash "$HERE/vps-external-ip-check.sh" "$IP" 443 > "$IPAUDIT_LOG" 2>&1 || true
  PXC_FRAUD=$(grep -oE 'Fraud Score *: *[0-9]+' "$IPAUDIT_LOG" 2>/dev/null | grep -oE '[0-9]+' | head -1)
  PXC_ABUSE=$(grep -oE '被举报次数: *[0-9]+' "$IPAUDIT_LOG" 2>/dev/null | grep -oE '[0-9]+' | head -1)
  echo "  报告已存: $IPAUDIT_LOG"
fi

if [ "$DO_DEEP" = "1" ]; then
  echo ""
  if [ -z "$KEY" ]; then
    echo "  ⚠️  --deep 需要 SSH 密钥（NodeQuality 要维持 10-20 分钟长连接，密码模式不稳）"
    echo "      先 ssh-copy-id -p $PORT root@${IP}，或改用 --key <私钥>"
  else
    if [ "${DEEP_FULL:-0}" = "1" ]; then DEEP_MODE="全量"; DEEP_ARG=""; else DEEP_MODE="低流量"; DEEP_ARG="--lowdata"; fi
    echo "  NodeQuality 深度报告（${DEEP_MODE}模式，10-20 分钟，跑完会删本地结果）..."
    mkdir -p "$HOME/.vps-node"; chmod 700 "$HOME/.vps-node" 2>/dev/null
    DEEP_LOG="$HOME/.vps-node/precheck-${IP}-quality-$(date +%Y%m%d-%H%M).log"
    SSH_KEY="$KEY" bash "$HERE/vps-quality-report.sh" "$IP" "$PORT" $DEEP_ARG > "$DEEP_LOG" 2>&1 || true
    echo "  报告已存: $DEEP_LOG"
    DEEP_URL=$(grep -oE 'https://nodequality\.com/r/[A-Za-z0-9]+' "$DEEP_LOG" 2>/dev/null | head -1)
    [ -n "$DEEP_URL" ] && echo "  公开报告: $DEEP_URL"
  fi
fi

# ---------------------------------------------------------------- 3. 判定
FAILS=""; WARNS=""
fail() { FAILS="$FAILS
  ❌ $1"; }
warn() { WARNS="$WARNS
  ⚠️  $1"; }

num() { case "$1" in ''|*[!0-9.]*) echo 0 ;; *) echo "$1" ;; esac; }

[ "$(num "$DISK_FREE_MB")" -lt 2000 ] && fail "磁盘可用 ${DISK_FREE_MB} MB < 2000 MB，装不下 sing-box + 日志 + 证书"
[ "$(num "$DISK_FREE_MB")" -ge 2000 ] && [ "$(num "$DISK_FREE_MB")" -lt 5000 ] && warn "磁盘可用 ${DISK_FREE_MB} MB < 5 GB，长期跑日志会紧"
[ "$(num "$MEM_MB")" -lt 256 ] && fail "内存 ${MEM_MB} MB < 256 MB，sing-box + fail2ban 会吃紧"
[ "$(num "$MEM_MB")" -ge 256 ] && [ "$(num "$MEM_MB")" -lt 512 ] && warn "内存 ${MEM_MB} MB < 512 MB，多协议并发时留意 OOM"
[ "$NET_GITHUB" != "200" ] && fail "出网异常：github 返回 ${NET_GITHUB}，装不了 sing-box"
[ "$VIRT_OPENVZ" = "1" ] && fail "OpenVZ/LXC 容器，内核参数不可改，BBR 与 sysctl 加固都无法生效"
[ "$PORT_443" != "0" ] && [ "$PORT_443" != "NA" ] && warn "443 端口已被占用（${PORT_443} 个监听），REALITY 需要它"
[ "$EXIST_SINGBOX" = "yes" ] && warn "已存在 sing-box（重装会覆盖 /etc/sing-box/config.json）"
[ "$EXIST_XRAY" = "yes" ] && warn "已存在 xray（可能占用 443）"
[ "$EXIST_3XUI" = "yes" ] && warn "已存在 3x-ui 面板（可能占用 443/80）"
IO_NUM=$(echo "$DISK_IO" | grep -oE '^[0-9]+' | head -1)
if [ -n "$IO_NUM" ] && [ "$IO_NUM" -lt 50 ]; then
  warn "磁盘写速 ${DISK_IO} < 50 MB/s，可能是严重超售"
fi
[ "$SPEED_MBPS" != "SKIPPED" ] && [ "$SPEED_MBPS" != "" ] && \
  awk -v v="$SPEED_MBPS" 'BEGIN{exit !(v+0 < 20)}' 2>/dev/null && \
  warn "实测下行 ${SPEED_MBPS} Mbps < 20 Mbps，与标称带宽差距大"
[ "$PXC_RISK" != "" ] && awk -v v="$PXC_RISK" 'BEGIN{exit !(v+0 >= 40)}' 2>/dev/null && \
  warn "proxycheck 风险分 ${PXC_RISK}/100（>=40），AI 站可能要求人机验证"
[ "$IP_PROXY" = "True" ] || [ "$IP_PROXY" = "true" ] && warn "ip-api 标记为代理出口（proxy=yes），对 Claude/ChatGPT 风控不利"
[ -z "$RET_BOUTIQUE" ] && warn "回程未见 9929 / 4809 / CUG / CMIN2 精品段（AS: ${RET_AS:-未知}），高峰可能绕路"

# AI 站可达性（本机直连，不经节点）
# 注意：403 + cf-mitigated 在「机房 IP + 裸 curl」场景下是常态（没有 JS 环境与浏览器指纹），
# 不代表用户真浏览器走节点时也会被挡。所以这里只判「网络层能不能通」，风控留给部署后的 --browser 实测。
case "$AI_CLAUDE" in
  000|"") fail "claude.ai 完全连不上（网络层不通）" ;;
esac
case "$AI_CHATGPT" in
  000|"") fail "chatgpt.com 完全连不上（网络层不通）" ;;
esac
case "$AI_ANTHROPIC" in
  000|"") warn "api.anthropic.com 连不上，AI API 可能不可达" ;;
esac

# 可选深度检查结论
if [ -n "$PXC_FRAUD" ]; then
  awk -v v="$PXC_FRAUD" 'BEGIN{exit !(v+0 >= 50)}' && fail "Scamalytics Fraud Score ${PXC_FRAUD}/100（≥50，高风险 IP）"
  awk -v v="$PXC_FRAUD" 'BEGIN{exit !(v+0 >= 25 && v+0 < 50)}' && warn "Scamalytics Fraud Score ${PXC_FRAUD}/100（≥25，偏高）"
fi
if [ -n "$PXC_ABUSE" ] && [ "$PXC_ABUSE" != "0" ]; then
  warn "AbuseIPDB 被举报 ${PXC_ABUSE} 次（同段滥用历史）"
fi

# ---------------------------------------------------------------- 4. 输出
# 按显示宽度对齐：中文占 2 列，printf 的 %-Ns 按字节算会错位
pad() {
  python3 -c '
import sys, unicodedata
s = sys.argv[1]; w = int(sys.argv[2])
d = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
sys.stdout.write(s + " " * max(0, w - d))
' "$1" "$2"
}
row() { echo "  $(pad "$1" 11)$2"; }

echo ""
echo "────────────── 机器 ──────────────"
row "系统"     "${OS:-未知} · kernel ${KERNEL:-?} · ${ARCH:-?}"
row "CPU"      "${CPU_CORE:-?} 核 · ${CPU_MODEL:-未知}"
row "内存"     "${MEM_MB:-?} MB"
row "磁盘"     "$(awk -v v="$(num "$DISK_TOTAL_MB")" 'BEGIN{printf "%.0f", v/1024}') GB 总 / $(awk -v v="$(num "$DISK_FREE_MB")" 'BEGIN{printf "%.1f", v/1024}') GB 可用"
row "虚拟化"   "${VIRT:-none}$([ "$VIRT_OPENVZ" = "1" ] && echo ' (容器，不支持 BBR)')"
row "拥塞控制" "${CC:-NA}$([ "$CC" = "bbr" ] && echo ' (已开 BBR)' || echo ' (部署时开 BBR)')"
DIO_SHOW="$DISK_IO"; [ "$DISK_IO" = "SKIPPED" ] && DIO_SHOW="未测"
row "磁盘写速" "${DIO_SHOW:-NA}   在线 ${UPTIME_H:-?} 小时   负载 ${LOAD1:-?}"
if [ "$SPEED_MBPS" = "SKIPPED" ] || [ -z "$SPEED_MBPS" ]; then SP_SHOW="未测"
else SP_SHOW="${SPEED_MBPS} Mbps"; fi
row "下行实测" "$SP_SHOW"
row "出网"     "github ${NET_GITHUB:-?} · cloudflare ${NET_CLOUDFLARE:-?}"
row "端口"     "443:${PORT_443:-?}  80:${PORT_80:-?}"
row "已装"     "sing-box ${EXIST_SINGBOX:-?} · xray ${EXIST_XRAY:-?} · 3x-ui ${EXIST_3XUI:-?}"

echo ""
echo "────────────── IP 质量（${IP}）──────────────"
row "归属"     "${IP_COUNTRY:-?} ${IP_REGION:-?} ${IP_CITY:-?}"
row "运营商"   "${IP_ISP:-?}"
row "ASN"      "${IP_AS:-?}"
row "标记"     "proxy=${IP_PROXY:-?}  hosting=${IP_HOSTING:-?}"
if [ -n "$PXC_RISK" ]; then
  row "proxycheck" "risk=${PXC_RISK}/100  proxy=${PXC_PROXY:-?}  type=${PXC_TYPE:-?}"
else
  row "proxycheck" "无响应（限额或网络）"
fi
if [ -n "$EGRESS_JSON" ]; then
  EG_IP=$(J "$EGRESS_JSON" "query")
  [ -z "$EG_IP" ] && EG_IP=$(curl -s --max-time 6 https://api.ip.sb/ip 2>/dev/null | tr -d ' \n')
  row "出口 IP" "${EG_IP:-?}$([ -n "$EG_IP" ] && [ "$EG_IP" != "$IP" ] && echo '   ← 与购买 IP 不一致！')"
fi

echo ""
echo "────────────── AI 站可达性（VPS 本机直连，不经节点）──────────────"
land_desc() {   # $1=状态码 $2=cf-mitigated 命中数
  case "$1" in
    000|"")              echo "连不上" ;;
    200|301|302|307|308) echo "可达" ;;
    401|403|404|405)     if [ "${2:-0}" != "0" ]; then
                           echo "CF 挑战（机房 IP + 裸 curl 的常态，仅参考）"
                         else
                           echo "可达（裸 curl 的正常拒绝）"
                         fi ;;
    *)                   echo "HTTP $1" ;;
  esac
}
echo "  $(pad "claude.ai" 18)HTTP ${AI_CLAUDE:-?}   $(land_desc "$AI_CLAUDE" "$AI_CLAUDE_CF")"
echo "  $(pad "chatgpt.com" 18)HTTP ${AI_CHATGPT:-?}   $(land_desc "$AI_CHATGPT" "$AI_CHATGPT_CF")"
echo "  $(pad "api.anthropic.com" 18)HTTP ${AI_ANTHROPIC:-?}   $(land_desc "$AI_ANTHROPIC" "0")"

echo ""
echo "────────────── 回程（→ ${TARGET}）──────────────"
if echo "$TRACE_BLOCK" | grep -q 'TRACE_UNAVAILABLE'; then
  echo "  nexttrace / mtr 均不可用（apt 或外网受限），此项跳过"
elif [ -z "$TRACE_BLOCK" ]; then
  echo "  探测无输出（目标不响应 ICMP？换 TARGET=<家宽IP> 再试）"
else
  echo "$TRACE_BLOCK" | head -26 | sed 's/^/  /'
  echo "  ▶ AS 路径: ${RET_AS:-未知}"
  if [ -n "$RET_BOUTIQUE" ]; then
    echo "  ▶ 精品段: $RET_BOUTIQUE"
  else
    echo "  ▶ 未见精品段（工具: ${TRACE_TOOL}）"
  fi
fi

echo ""
echo "────────────── 结论 ──────────────"
if [ -n "$FAILS" ]; then
  echo "$FAILS"
  [ -n "$WARNS" ] && echo "$WARNS"
  echo ""
  echo "  ❌ 不建议部署 —— 先联系商家换 IP / 换机器 / 退款，再回来跑部署"
  [ -n "$IPAUDIT_LOG" ] && echo "  📄 IP 体检报告: $IPAUDIT_LOG"
  [ -n "$IPAUDIT_LOG" ] && echo "  📄 IP 体检报告: $IPAUDIT_LOG"
  [ "$FORCE" = "1" ] && { echo "  （FORCE=1，仍继续）"; exit 0; }
  exit 2
elif [ -n "$WARNS" ]; then
  echo "$WARNS"
  echo ""
  echo "  ⚠️  可以部署，但有上面这些需要留意的地方"
  [ -n "$IPAUDIT_LOG" ] && echo "  📄 IP 体检报告: $IPAUDIT_LOG"
  [ -n "$DEEP_LOG" ] && echo "  📄 深度报告: $DEEP_LOG"
  exit 1
else
  echo "  ✅ 通过 —— 机器与 IP 都达标，可以开始部署"
  [ -n "$IPAUDIT_LOG" ] && echo "  📄 IP 体检报告: $IPAUDIT_LOG"
  [ -n "$DEEP_LOG" ] && echo "  📄 深度报告: $DEEP_LOG"
  exit 0
fi
