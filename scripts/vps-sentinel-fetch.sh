#!/bin/bash
# ============================================================================
# 拉取服务端哨兵日志并分析（Mac 侧执行）
#
# VPS 每 10 分钟写一行 JSONL，本脚本把整份日志拉回本地，结合一次
# 「本机真实探测」做合并分析：服务端能证明「机器还活着、出口没变、
# 证书没过期」，本机能证明「国内还能连上」——两者缺一不可。
#
# 用法:
#   vps-sentinel-fetch.sh <凭据别名 | creds.json | IP> [选项]
#
# 选项:
#   --json      机读输出（automation 判断用）
#   --full      展开每一条异常原始记录（默认只给聚合摘要）
#   --no-local  跳过本机真实探测（只分析远端日志）
#   --risk      本机探测附带 IP 风险复检（透传给 vps-sentinel.sh --risk）
#   --days N    只看最近 N 天，默认 1（日检只对最近 24h 定级）；0 = 全部
#
# 退出码: 0 正常 / 1 警告 / 2 严重
# ============================================================================
set -uo pipefail

ARG="${1:-}"
[ -n "$ARG" ] || { echo "用法: vps-sentinel-fetch.sh <凭据别名 | creds.json | IP> [--json] [--full] [--no-local] [--risk] [--days N]"; exit 1; }
shift || true

JSONOUT=0; FULL=0; DOLOCAL=1; DAYS=1; RISKARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json)     JSONOUT=1; shift ;;
    --full)     FULL=1; shift ;;
    --no-local) DOLOCAL=0; shift ;;
    --risk)     RISKARG="--risk"; shift ;;
    --days)     DAYS="${2:-1}"; shift 2
                case "$DAYS" in ''|*[!0-9]*) echo "--days 需要非负整数"; exit 1 ;; esac ;;
    *) echo "未知选项: $1"; exit 1 ;;
  esac
done

HERE=$(cd "$(dirname "$0")" && pwd)

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
  IP=$(J ip); FQDN=$(J fqdn); SSH_PORT_C=$(J ssh_port); HOME_IP=$(J home_ip)
else
  IP="$ARG"; FQDN=""; SSH_PORT_C=""; HOME_IP=""
fi
[ -n "$IP" ] || { echo "无法确定 IP"; exit 1; }
NAME="${FQDN:-$IP}"
ALIAS=$(basename "${CREDS:-$IP}" .json)
LOCAL_LOG="$HOME/.vps-node/${ALIAS}-sentinel.jsonl"

# ---- SSH 探测：统一约定键 → 别名键 → 泛化 → 通用默认 ----
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
for p in ${SSH_PORT_C:-} 22 2222; do
  [ -z "$p" ] && continue
  if ssh $SSHBASE -p "$p" "root@$IP" 'echo OK' 2>/dev/null | grep -q OK; then PORT="$p"; break; fi
done

REMOTE_LINES=0
if [ -z "$PORT" ]; then
  echo "🔴 SSH 不可达（${IP}，端口试过 ${SSH_PORT_C:-} 22 2222）——取不到服务端日志" >&2
  [ -s "$LOCAL_LOG" ] && echo "   本地缓存仍可分析：$(wc -l < "$LOCAL_LOG" | tr -d ' ') 条" >&2
else
  mkdir -p "$HOME/.vps-node" && chmod 700 "$HOME/.vps-node" 2>/dev/null
  ssh $SSHBASE -p "$PORT" "root@$IP" 'cat /var/log/vps-sentinel/sentinel.jsonl 2>/dev/null' > "$LOCAL_LOG.new" 2>/dev/null
  if [ -s "$LOCAL_LOG.new" ]; then
    mv "$LOCAL_LOG.new" "$LOCAL_LOG"
  else
    rm -f "$LOCAL_LOG.new"
  fi
  REMOTE_LINES=$( [ -f "$LOCAL_LOG" ] && wc -l < "$LOCAL_LOG" | tr -d ' ' || echo 0 )
fi

# ---- 本机真实探测（能看国内 → VPS 的唯一视角）----
LOCAL_JSON=""
if [ "$DOLOCAL" = "1" ]; then
  LOCAL_JSON=$(bash "$HERE/vps-sentinel.sh" "$ALIAS" --json $RISKARG 2>/dev/null || true)
  [ -z "$LOCAL_JSON" ] && LOCAL_JSON=$(bash "$HERE/vps-sentinel.sh" "$IP" --json $RISKARG 2>/dev/null || true)
fi

# ---- 分析 ----
export REMOTE_LINES LOCAL_JSON NAME IP HOME_IP FULL DAYS JSONOUT
python3 - "$LOCAL_LOG" <<'PY'
import json, os, sys, statistics
from datetime import datetime, timezone, timedelta

path = sys.argv[1]
expected_ip = os.environ.get("IP", "")
name = os.environ.get("NAME", expected_ip)
home_ip = os.environ.get("HOME_IP", "")
full = os.environ.get("FULL") == "1"
days = int(os.environ.get("DAYS") or 0)
jsonout = os.environ.get("JSONOUT") == "1"

rows = []
try:
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                pass
except FileNotFoundError:
    rows = []

def ts(x):
    try:
        return datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None

rows = [r for r in rows if ts(r.get("ts", ""))]
rows.sort(key=lambda r: r["ts"])
if days > 0 and rows:
    cut = datetime.now(timezone.utc) - timedelta(days=days)
    rows = [r for r in rows if ts(r["ts"]) >= cut]

def pct(a, b):
    return 100.0 * a / b if b else 0.0

def mmss(sec):
    if sec is None:
        return "—"
    h = sec // 3600
    if h >= 48:
        return f"{h//24}天"
    if h >= 1:
        return f"{h}小时"
    return f"{sec//60}分钟"

anom = []   # (kind, level, detail, ts)

def add(kind, level, detail, t):
    anom.append({"kind": kind, "level": level, "detail": detail, "ts": t})

if not rows:
    out = {"name": name, "samples": 0, "level": 1,
           "issues": ["服务端日志为空（或 --days 窗口内无样本）：确认已装 cron（/etc/cron.d/vps-sentinel）"]}
    if jsonout:
        print(json.dumps(out, ensure_ascii=False))
    else:
        print(f"⚠️  {name}：没有拿到服务端日志")
        print("   检查：ssh 上去 `ls -l /var/log/vps-sentinel/` 与 `cat /etc/cron.d/vps-sentinel`")
    sys.exit(1)

n = len(rows)
t0, t1 = ts(rows[0]["ts"]), ts(rows[-1]["ts"])
span_min = (t1 - t0).total_seconds() / 60
gaps = []
for a, b in zip(rows, rows[1:]):
    d = (ts(b["ts"]) - ts(a["ts"])).total_seconds() / 60
    if d > 0:
        gaps.append(d)
med_gap = statistics.median(gaps) if gaps else 10.0
expected_n = span_min / med_gap + 1 if med_gap else n
coverage = min(99.9, pct(n, expected_n))

# 基础可用率
sb_ok = sum(1 for r in rows if r.get("sb") == "active")
sub_ok = sum(1 for r in rows if r.get("subsvc") == "active")
p443_ok = sum(1 for r in rows if r.get("p443") == 1)

for r in rows:
    if r.get("sb") != "active":
        add("singbox", 2, f"sing-box {r.get('sb')}", r["ts"])
    elif r.get("p443") != 1:
        add("port443", 1, f"443 监听数 {r.get('p443')}", r["ts"])
    if r.get("subsvc") not in (None, "", "active"):
        add("subsvc", 1, f"订阅服务 {r.get('subsvc')}", r["ts"])

# 出口 IP
eg = [(r["ts"], str(r.get("egress") or "")) for r in rows if r.get("egress")]
eg_vals = {}
for t, v in eg:
    if v not in eg_vals:
        eg_vals[v] = [t, t, 0]
    eg_vals[v][1] = t
    eg_vals[v][2] += 1
for v, (ft, lt, c) in eg_vals.items():
    if expected_ip and v != expected_ip:
        add("egress", 2, f"出口 {v}（应为 {expected_ip}），首次 {ft}", ft)

# 证书
cert_v = [r["cert"] for r in rows if isinstance(r.get("cert"), int)]
sub_v = [(r["ts"], str(r.get("sub") or "")) for r in rows if r.get("sub")]
for t, v in sub_v:
    if v == "000":
        add("sub_http", 2, "订阅本地自取失败（000）", t)
    elif v not in ("200", "0", ""):
        add("sub_http", 2, f"订阅本地自取 HTTP {v}", t)

# 落地风控
land_v = {}
for r in rows:
    v = r.get("landing") or ""
    if not v:
        continue
    if v not in land_v:
        land_v[v] = [r["ts"], r["ts"], 0]
    land_v[v][1] = r["ts"]
    land_v[v][2] += 1
for v, (ft, lt, c) in land_v.items():
    bad = any(k in v for k in ("chatgpt=403", "anthropic=403", "chatgpt=000", "anthropic=000"))
    if bad:
        add("landing", 1, f"落地风控 {v}", ft)

# 回程延迟 / 丢包
cp = []
for r in rows:
    c = r.get("cping") or ""
    if "/" in c:
        try:
            mn, av = c.split("/")[:2]
            cp.append((r["ts"], float(mn), float(av)))
        except Exception:
            pass
cp_anom = []
for t, mn, av in cp:
    if av > 400:
        cp_anom.append((t, av))
        add("cping", 1, f"回程延迟 {av:.0f}ms", t)
loss_v = [(r["ts"], r["loss"]) for r in rows if isinstance(r.get("loss"), int)]
for t, v in loss_v:
    if v >= 20:
        add("loss", 1, f"回程丢包 {v}%", t)
    elif v > 0:
        add("loss_minor", 1, f"回程丢包 {v}%", t)

# 重启 / 磁盘 / 风险
for r in rows:
    if r.get("reboot") == 1:
        add("reboot", 1, "检测到重启（uptime < 15 分钟）", r["ts"])
    d = r.get("disk")
    if isinstance(d, int) and d < 500:
        add("disk", 2, f"磁盘仅剩 {d}MB", r["ts"])

fraud = [(r["ts"], r["fraud"]) for r in rows if isinstance(r.get("fraud"), int)]
for t, v in fraud:
    if v >= 40:
        add("fraud", 1, f"Fraud Score {v}", t)

trace_v = [r["trace"] for r in rows if r.get("trace")]
proxy_v = [r["proxy"] for r in rows if r.get("proxy")]

# 聚合
groups = {}
for a in anom:
    g = groups.setdefault(a["kind"], {"level": a["level"], "count": 0, "first": a["ts"], "last": a["ts"], "sample": a["detail"]})
    g["count"] += 1
    g["last"] = a["ts"]
    g["level"] = max(g["level"], a["level"])

LEVEL = max([a["level"] for a in anom], default=0)
# 只有严重项才算 2；单次轻微不升级
if any(a["level"] == 2 for a in anom):
    LEVEL = 2
elif anom:
    LEVEL = 1
else:
    LEVEL = 0

local = {}
try:
    if os.environ.get("LOCAL_JSON"):
        local = json.loads(os.environ["LOCAL_JSON"])
except Exception:
    local = {}

if jsonout:
    out = {
        "name": name,
        "ip": expected_ip,
        "samples": n,
        "first": rows[0]["ts"],
        "last": rows[-1]["ts"],
        "coverage": round(coverage, 1),
        "sb_uptime": round(pct(sb_ok, n), 1),
        "p443_ok": round(pct(p443_ok, n), 1),
        "egress": list(eg_vals.keys()),
        "cert_days": min(cert_v) if cert_v else None,
        "cping_avg": round(statistics.median([x[2] for x in cp]), 1) if cp else None,
        "loss_max": max([v for _, v in loss_v], default=None),
        "landing": list(land_v.keys()),
        "fraud_max": max([v for _, v in fraud], default=None),
        "local_level": local.get("level"),
        "local_delay": local.get("delay_reality"),
        "level": max(LEVEL, int(local.get("level") or 0)),
        "issues": [f"{k}({g['count']}次) {g['sample']} @ {g['first']}" for k, g in groups.items()],
    }
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(max(LEVEL, int(local.get("level") or 0)))

# ---------- 人类可读 ----------
L = []
L.append(f"=== 服务端哨兵 · {name} ===")
L.append(f"区间   : {rows[0]['ts']} → {rows[-1]['ts']}")
L.append(f"样本   : {n} 条 / 间隔中位数 {med_gap:.0f} 分钟 / 覆盖率 {coverage:.1f}%")
L.append(f"可用   : sing-box {pct(sb_ok,n):.1f}% · 443 监听 {pct(p443_ok,n):.1f}% · 订阅服务 {pct(sub_ok,n):.1f}%")
if eg:
    if len(eg_vals) == 1:
        L.append(f"出口   : {list(eg_vals)[0]}（稳定，{len(eg)} 次采样）")
    else:
        parts = [f"{v}×{c}" for v, (_, _, c) in eg_vals.items()]
        L.append(f"出口   : {len(eg_vals)} 个值！ {' / '.join(parts)}")
if cp:
    avs = [x[2] for x in cp]
    L.append(f"回程   : 中位 {statistics.median(avs):.0f}ms · P95 {sorted(avs)[int(len(avs)*0.95)-1 if len(avs)>1 else 0]:.0f}ms · 最大 {max(avs):.0f}ms · 采样 {len(cp)} 次")
else:
    L.append("回程   : 未采集（安装时没给 --home-ip）")
if loss_v:
    L.append(f"丢包   : 峰值 {max(v for _, v in loss_v)}%")
if cert_v:
    L.append(f"证书   : 剩余 {cert_v[-1]} 天（区间最低 {min(cert_v)} 天）")
if land_v:
    L.append("风控   : " + " | ".join(f"{v}×{c}" for v, (_, _, c) in land_v.items()))
if fraud:
    L.append(f"风险   : Fraud 最高 {max(v for _, v in fraud)}" + (f" · {proxy_v[-1]}" if proxy_v else ""))
disk_v = [r["disk"] for r in rows if isinstance(r.get("disk"), int)]
if disk_v:
    L.append(f"磁盘   : 最低 {min(disk_v)}MB")
rb = [a for a in anom if a["kind"] == "reboot"]
L.append(f"重启   : {len(rb)} 次" + (f"（最近 {rb[-1]['ts']}）" if rb else ""))
if trace_v:
    L.append(f"回程AS : {trace_v[-1]}")

if local:
    L.append("")
    L.append("=== 本机真实探测（唯一能看「国内 → VPS」的视角）===")
    lv = int(local.get("level") or 0)
    icon = {0: "✅", 1: "⚠️", 2: "🔴"}.get(lv, "•")
    L.append(f"{icon} REALITY {local.get('delay_reality') or '—'}ms · Hy2 {local.get('delay_hy2') or '—'}ms · 出口 {local.get('egress') or '—'} · 证书 {local.get('cert_days') or '—'}天")
    if local.get("issues"):
        L.append("   " + "; ".join(local["issues"]))

L.append("")
if not groups:
    L.append("=== 结论 ===")
    L.append("✅ 服务端全程无异常")
else:
    L.append("=== 异常 ===")
    for k, g in sorted(groups.items(), key=lambda x: (-x[1]["level"], -x[1]["count"])):
        icon = "🔴" if g["level"] == 2 else "⚠️"
        L.append(f"{icon} {k}: {g['count']} 次 | {g['sample']} | 首次 {g['first']} 末次 {g['last']}")
    if full:
        L.append("")
        L.append("--- 原始记录 ---")
        for a in anom[:200]:
            L.append(f"{a['ts']}  {a['kind']:10s} {a['detail']}")
        if len(anom) > 200:
            L.append(f"... 其余 {len(anom)-200} 条省略")

print("\n".join(L))
sys.exit(LEVEL)
PY

RC=$?
exit "$RC"
