#!/bin/bash
# ============================================================================
# 在 VPS 上安装服务端哨兵（Mac 侧执行）
#
# 做四件事：上传采集器 → 写 /etc/vps-sentinel.conf → 装 cron（每 10 分钟）
#           → 立即跑一次全量采集并验证。幂等，可重复执行。
#
# 用法:
#   vps-sentinel-install.sh <凭据别名 | creds.json | IP> [选项]
#
# 选项:
#   --home-ip <IP>     国内家宽出口 IP，用于回程延迟与 AS 路径（强烈建议给）
#   --interval <分钟>  cron 间隔，默认 10
#   --no-landing       关闭 claude.ai / chatgpt.com 落地风控探测
#   --no-risk          关闭每日 IP 风险分抓取
#   --uninstall        卸载（停 cron、删脚本与配置，保留日志）
# ============================================================================
set -uo pipefail

ARG="${1:-}"
[ -n "$ARG" ] || { echo "用法: vps-sentinel-install.sh <凭据别名 | creds.json | IP> [--home-ip x.x.x.x] [--interval 10]"; exit 1; }
shift || true

HOME_IP=""; INTERVAL=10; LANDING=1; RISK=1; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --home-ip)    HOME_IP="${2:-}"; shift 2 ;;
    --interval)   INTERVAL="${2:-10}"; shift 2 ;;
    --no-landing) LANDING=0; shift ;;
    --no-risk)    RISK=0; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    *) echo "未知选项: $1"; exit 1 ;;
  esac
done

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
if [ -n "$CREDS" ]; then
  J(){ python3 -c "import json;print(json.load(open('$CREDS')).get('$1',''))" 2>/dev/null; }
  IP=$(J ip); FQDN=$(J fqdn); SUBURL=$(J sub_url)
  [ -z "$HOME_IP" ] && HOME_IP=$(J home_ip)
else
  IP="$ARG"; FQDN=""; SUBURL=""
fi
[ -n "$IP" ] || { echo "无法确定 IP"; exit 1; }
NAME="${FQDN:-$IP}"
ALIAS=$(basename "${CREDS:-$IP}" .json)

# ---- SSH 密钥 / 端口探测 ----
KEYOPT=""
for k in "$HOME/.ssh/id_ed25519_vps" "$HOME/.ssh/id_ed25519_${ALIAS:-}" \
         "$HOME/.ssh/id_ed25519_${FQDN%%.*}" "$HOME"/.ssh/id_ed25519_* \
         "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
  [ -f "$k" ] || continue
  case "$k" in *.pub) continue ;; esac
  KEYOPT="-i $k"; break
done
SSHBASE="$KEYOPT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o BatchMode=yes -o LogLevel=ERROR"

PORT=""
for p in $(python3 -c "import json;print(json.load(open('$CREDS')).get('ssh_port',''))" 2>/dev/null) 22 2222; do
  [ -z "$p" ] && continue
  if ssh $SSHBASE -p "$p" "root@$IP" 'echo OK' 2>/dev/null | grep -q OK; then PORT="$p"; break; fi
done
[ -n "$PORT" ] || { echo "❌ SSH 不通（密钥 ${KEYOPT:-默认} / 端口试过 22 2222）"; exit 1; }
echo "✅ SSH 就绪：$IP:$PORT"

if [ "$UNINSTALL" = "1" ]; then
  ssh $SSHBASE -p "$PORT" "root@$IP" 'bash -s' <<'REMOTE'
rm -f /etc/cron.d/vps-sentinel
rm -f /usr/local/bin/vps-sentinel-agent.sh
rm -f /etc/vps-sentinel.conf
echo "已卸载（日志保留在 /var/log/vps-sentinel）"
REMOTE
  exit 0
fi

# ---- 上传采集器 ----
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/vps-sentinel-agent.sh"
[ -f "$SRC" ] || { echo "❌ 找不到 $SRC"; exit 1; }
scp $SSHBASE -P "$PORT" -q "$SRC" "root@$IP:/usr/local/bin/vps-sentinel-agent.sh" || { echo "❌ 上传失败"; exit 1; }
echo "✅ 采集器已上传"

# ---- 写配置 + 装 cron + 立即跑一次 ----
SUB_PATH_TOKEN=""
ssh $SSHBASE -p "$PORT" "root@$IP" \
  "HOME_IP='$HOME_IP' INTERVAL='$INTERVAL' LANDING='$LANDING' RISK='$RISK' bash -s" <<'REMOTE'
set -e
chmod +x /usr/local/bin/vps-sentinel-agent.sh
mkdir -p /var/log/vps-sentinel && chmod 700 /var/log/vps-sentinel

cat > /etc/vps-sentinel.conf <<CONF
# 服务端哨兵配置（由 vps-sentinel-install.sh 生成）
HOME_IP="$HOME_IP"
SUB_PORT=2096
ENABLE_LANDING=$LANDING
ENABLE_RISK=$RISK
MAX_LINES=8000
KEEP_DAYS=30
CONF
chmod 600 /etc/vps-sentinel.conf

# cron 需要 cron 守护进程
if ! systemctl is-active --quiet cron 2>/dev/null && ! systemctl is-active --quiet crond 2>/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron >/dev/null 2>&1 || true
  systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 || true
fi

cat > /etc/cron.d/vps-sentinel <<CRON
# 服务端哨兵：每 $INTERVAL 分钟只读采集一次
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/$INTERVAL * * * * root /usr/local/bin/vps-sentinel-agent.sh >/dev/null 2>&1
CRON
chmod 644 /etc/cron.d/vps-sentinel

# 立即全量采集一次，验证链路
/usr/local/bin/vps-sentinel-agent.sh --all >/dev/null 2>&1 || true
echo "=== 首次采集 ==="
tail -1 /var/log/vps-sentinel/sentinel.jsonl 2>/dev/null | cut -c1-400
echo "=== 日志状态 ==="
wc -l /var/log/vps-sentinel/sentinel.jsonl 2>/dev/null || echo "no log"
echo "=== cron ==="
systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null || echo unknown
REMOTE

RC=$?
if [ "$RC" != "0" ]; then
  echo "❌ 安装过程返回 ${RC}，请检查上面的输出"
  exit "$RC"
fi

# ---- 把 home_ip 记进凭据，供后续 fetch 复用 ----
if [ -n "$CREDS" ] && [ -n "$HOME_IP" ]; then
  python3 - "$CREDS" "$HOME_IP" <<'PY'
import json,sys
p,v=sys.argv[1],sys.argv[2]
d=json.load(open(p))
if d.get("home_ip")!=v:
    d["home_ip"]=v
    json.dump(d,open(p,"w"),ensure_ascii=False,indent=2)
    print("已写入凭据 home_ip =",v)
PY
fi

echo ""
echo "✅ 安装完成 —— 之后 Mac 关机也不影响采集"
echo "   日志: $IP:/var/log/vps-sentinel/sentinel.jsonl（保留 30 天 / 8000 行）"
echo "   拉取: bash $(dirname "$0")/vps-sentinel-fetch.sh $ALIAS"
[ -n "$HOME_IP" ] || echo "   ⚠️ 未提供 --home-ip，回程延迟与 AS 路径将采集不到"
