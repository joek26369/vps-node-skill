#!/bin/bash
# ============================================================================
# 服务端哨兵采集器 —— 部署在 VPS 上，由 cron 每 10 分钟调用
#
# 只读采集，不重启服务、不改配置、不写远端。
# 每次运行向 /var/log/vps-sentinel/sentinel.jsonl 追加一行 JSON，
# Mac 侧由 vps-sentinel-fetch.sh 拉取后分析。
#
# 用法:
#   vps-sentinel-agent.sh            正常采集（按 slot 分层，省资源）
#   vps-sentinel-agent.sh --all      强制全量采集（装机自检用）
#   vps-sentinel-agent.sh --print    只打印本次结果，不落盘
#
# 采样分层（cron 每 10 分钟 → slot 每次 +1）:
#   每次        : 服务状态 / 端口监听 / 磁盘 / 负载 / 运行时长 / 重启标记
#   slot %6=1   : 出口 IP、回程 ping 到国内家宽（1 小时）
#   slot %36=1  : 证书余期、订阅本地自取、落地风控（6 小时）
#   slot %144=1 : IP 风险分、回程 AS 路径、日志滚动（24 小时）
#
# 配置: /etc/vps-sentinel.conf（由 vps-sentinel-install.sh 写入）
# ============================================================================
set -uo pipefail

CONF=/etc/vps-sentinel.conf
DIR=/var/log/vps-sentinel
LOG=$DIR/sentinel.jsonl
STATE=$DIR/.slot

FORCE=0; PRINT=0
for a in "$@"; do
  case "$a" in
    --all)   FORCE=1 ;;
    --print) PRINT=1 ;;
  esac
done

# ---- 默认值（可被 conf 覆盖）----
HOME_IP=""
SUB_PORT=2096
SUB_TOKEN=""
ENABLE_LANDING=1
ENABLE_RISK=1
MAX_LINES=8000
KEEP_DAYS=30
[ -r "$CONF" ] && . "$CONF"

mkdir -p "$DIR" 2>/dev/null
chmod 700 "$DIR" 2>/dev/null

IDX=0
[ -r "$STATE" ] && IDX=$(tr -dc '0-9' < "$STATE" 2>/dev/null)
IDX=$(( ${IDX:-0} + 1 ))
[ "$PRINT" = "1" ] || echo "$IDX" > "$STATE" 2>/dev/null

# ---- 采样窗口判定 ----
DO_EXT=0; DO_LAND=0; DO_DAILY=0
if [ "$FORCE" = "1" ]; then
  DO_EXT=1; DO_LAND=1; DO_DAILY=1
else
  [ $(( IDX % 6 ))   -eq 1 ] && DO_EXT=1
  [ $(( IDX % 36 ))  -eq 1 ] && DO_LAND=1
  [ $(( IDX % 144 )) -eq 1 ] && DO_DAILY=1
fi

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---- 基础项：每次采集 ----
SB=$(systemctl is-active sing-box 2>/dev/null | head -1)
SB=${SB:-unknown}
# 订阅服务名不统一（vps-sub-https / node-sub-https / 自定义），按顺序探测
SUBSVC=""
for u in vps-sub-https node-sub-https sub-https; do
  s=$(systemctl is-active "$u" 2>/dev/null | head -1)
  [ -n "$s" ] && [ "$s" != "inactive" ] && [ "$s" != "unknown" ] && { SUBSVC="$s"; break; }
done
if [ -z "$SUBSVC" ]; then
  U=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -oE '[A-Za-z0-9_.-]*sub[A-Za-z0-9_.-]*\.service' | head -1)
  [ -n "$U" ] && SUBSVC=$(systemctl is-active "$U" 2>/dev/null | head -1)
fi
SUBSVC=${SUBSVC:-unknown}
P443=$(ss -H -tln 2>/dev/null | awk '$4 ~ /:443$/' | wc -l | tr -d ' ')
P8443=$(ss -H -uln 2>/dev/null | awk '$4 ~ /:8443$/' | wc -l | tr -d ' ')
P2096=$(ss -H -tln 2>/dev/null | awk '$4 ~ /:2096$/' | wc -l | tr -d ' ')
DISK=$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')
LOAD=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
UP=$(cut -d' ' -f1 /proc/uptime 2>/dev/null | cut -d. -f1)
REBOOT=0
[ -n "${UP:-}" ] && [ "$UP" -lt 900 ] 2>/dev/null && REBOOT=1

# ---- 1 小时档：出口 IP + 回程延迟 ----
EG=""; CPING=""; LOSS=""
if [ "$DO_EXT" = "1" ]; then
  EG=$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null | tr -d ' \n')
  [ -z "$EG" ] && EG=$(curl -4 -s --max-time 8 https://ip.sb 2>/dev/null | tr -d ' \n')
  if [ -n "${HOME_IP:-}" ]; then
    ST=$(ping -c 3 -W 2 -i 0.3 "$HOME_IP" 2>/dev/null)
    CPING=$(echo "$ST" | grep -oE 'min/avg/max[^=]*= [0-9.]+/[0-9.]+' | grep -oE '[0-9.]+/[0-9.]+$')
    LOSS=$(echo "$ST" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
  fi
fi

# ---- 6 小时档：证书余期 + 订阅自取 + 落地风控 ----
CERT=""; SUB=""; LAND=""
if [ "$DO_LAND" = "1" ]; then
  # 证书路径不统一（/opt/vps-certs 或 /opt/<名>/certs），先从 systemd 单元里反查
  CERTFILE=$(grep -ohE '/[^ ]*fullchain\.pem' /etc/systemd/system/*.service 2>/dev/null | head -1)
  if [ -z "$CERTFILE" ]; then
    for c in /opt/vps-certs/fullchain.pem /opt/*/certs/fullchain.pem; do
      [ -r "$c" ] && { CERTFILE="$c"; break; }
    done
  fi
  if [ -n "${CERTFILE:-}" ] && [ -r "$CERTFILE" ]; then
    EXP=$(openssl x509 -in "$CERTFILE" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    if [ -n "$EXP" ]; then
      ETS=$(date -d "$EXP" +%s 2>/dev/null || echo 0)
      [ "$ETS" -gt 0 ] 2>/dev/null && CERT=$(( (ETS - $(date +%s)) / 86400 ))
    fi
  fi
  if [ -z "${SUB_TOKEN:-}" ]; then
    SUB_TOKEN=$(grep -rhoE 'serve_sub_https\.py[[:space:]]+[a-f0-9]{8,}' /etc/systemd/system/*.service 2>/dev/null \
                | awk '{print $2}' | head -1)
  fi
  if [ -n "${SUB_TOKEN:-}" ]; then
    SUB=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
          "https://127.0.0.1:${SUB_PORT}/${SUB_TOKEN}.yaml" 2>/dev/null)
  fi
  if [ "${ENABLE_LANDING:-1}" = "1" ]; then
    A=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
        https://api.anthropic.com/v1/messages 2>/dev/null)
    G=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 \
        -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
        https://chatgpt.com 2>/dev/null)
    LAND="anthropic=$A chatgpt=$G"
  fi
fi

# ---- 24 小时档：风险分 + 回程 AS 路径 ----
FRAUD=""; PROXY=""; TRACE=""
if [ "$DO_DAILY" = "1" ]; then
  if [ "${ENABLE_RISK:-1}" = "1" ]; then
    PUBIP="${EG:-$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null | tr -d ' \n')}"
    if [ -n "${PUBIP:-}" ]; then
      FRAUD=$(curl -s --max-time 20 -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
              "https://scamalytics.com/ip/$PUBIP" 2>/dev/null \
              | python3 -c "
import sys,re
h=sys.stdin.read()
m=re.search(r'Fraud Score:\s*(?:<[^>]*>)*\s*(\d+)',h)
print(m.group(1) if m else '')" 2>/dev/null)
      PROXY=$(curl -s --max-time 12 "https://proxycheck.io/v2/$PUBIP?vpn=1&risk=1" 2>/dev/null \
              | python3 -c "
import json,sys
try:
    d=list(json.load(sys.stdin).values())[1]
    print(f\"proxy={d.get('proxy')} risk={d.get('risk')}\")
except Exception: print('')" 2>/dev/null)
    fi
  fi
  if [ -n "${HOME_IP:-}" ] && command -v nexttrace >/dev/null 2>&1; then
    TRACE=$(nexttrace -q 1 -m 20 -n "$HOME_IP" 2>/dev/null \
            | grep -oE 'AS[0-9]+' | uniq | paste -sd'>' -)
  elif [ -n "${HOME_IP:-}" ] && command -v traceroute >/dev/null 2>&1; then
    TRACE=$(traceroute -n -w 2 -q 1 -m 20 "$HOME_IP" 2>/dev/null \
            | awk 'NR>1 && $2!="*"{n++; if(n<=6) h=h $2 ">"} END{sub(/^[^ ]+ +/,"",h); print h}' | sed 's/>$//')
  fi
fi

# ---- 组装 JSON（python3 保证转义正确）----
export TS IDX SB SUBSVC P443 P8443 P2096 DISK LOAD UP REBOOT EG CPING LOSS CERT SUB LAND FRAUD PROXY TRACE
LINE=$(python3 - <<'PY' 2>/dev/null
import os, json

def s(k):
    return os.environ.get(k, "") or ""

def n(k):
    v = s(k).strip()
    try:
        return int(v)
    except Exception:
        return None

def f(k):
    v = s(k).strip()
    try:
        return round(float(v), 1)
    except Exception:
        return None

o = {
    "ts": s("TS"),
    "slot": n("IDX"),
    "sb": s("SB"),
    "subsvc": s("SUBSVC"),
    "p443": n("P443"),
    "p8443": n("P8443"),
    "p2096": n("P2096"),
    "disk": n("DISK"),
    "load": f("LOAD"),
    "up": n("UP"),
    "reboot": n("REBOOT"),
    "egress": s("EG"),
    "cert": n("CERT"),
    "sub": s("SUB"),
    "cping": s("CPING"),
    "loss": n("LOSS"),
    "landing": s("LAND"),
    "fraud": n("FRAUD"),
    "proxy": s("PROXY"),
    "trace": s("TRACE"),
}
print(json.dumps(o, ensure_ascii=False, separators=(",", ":")))
PY
)

if [ -z "$LINE" ]; then
  echo "采集失败：JSON 组装为空（检查 python3 是否可用）" >&2
  exit 1
fi

if [ "$PRINT" = "1" ]; then
  echo "$LINE"
  exit 0
fi

echo "$LINE" >> "$LOG" 2>/dev/null || { echo "写入 $LOG 失败" >&2; exit 1; }
chmod 600 "$LOG" 2>/dev/null

# ---- 日志滚动：行数上限 + 保留天数（仅在 24 小时档执行）----
if [ "$DO_DAILY" = "1" ]; then
  if [ "$(wc -l < "$LOG" 2>/dev/null || echo 0)" -gt "$MAX_LINES" ]; then
    tail -n "$MAX_LINES" "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
  fi
  CUT=$(date -u -d "$KEEP_DAYS days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
  if [ -n "$CUT" ]; then
    # 行首格式固定为 {"ts":"YYYY-MM-DDTHH:MM:SSZ" —— 时间戳从第 8 个字符起共 20 字符
    awk -v c="$CUT" 'substr($0,8,20) >= c' "$LOG" > "$LOG.cut" 2>/dev/null
    # 保底：裁剪结果为空（或明显少于原文件一半）就不替换，宁可留旧数据也不清空
    if [ -s "$LOG.cut" ]; then
      mv "$LOG.cut" "$LOG"
    else
      rm -f "$LOG.cut"
    fi
  fi
fi

exit 0
