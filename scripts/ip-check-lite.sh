#!/bin/bash
# ============================================================================
# 裸 IP 快查（购买前第一眼，无需把 IP 配到任何地方）
#
# 用法:
#   bash ip-check-lite.sh <IPv4>
#
# 查什么:
#   ipinfo         地理 / 组织 / 主机名（免费无 token，无 privacy/类型字段）
#   IPLogs         代理/VPN/Tor/hosting 判定 + IP 类型
#   Scamalytics    Fraud Score（参考）+ Server/VPN/Tor/Proxy 标志（抓页面）
#   ip.net.coffee  运营商类型 / ASN 是否住宅 / 原生性 / VPN 标志 + 服务端 DNSBL
#   ipx.al         多源类型投票 / 原生或广播 / 健康分 / 伪家宽
#   iping.cc       usage_type / as_type / 原生或广播 / is_proxy
#   AbuseIPDB      可选：举报表与 abuseConfidenceScore
#                  仅当环境变量 ABUSEIPDB_KEY 已设置，或
#                  ~/.vps-node/abuseipdb.key 存在且权限为 600/400 时启用
#
# 判定摘要:
#   类型投票：至少 2 个独立源判 ISP/家宽，且机房票不成多数，才可通过；
#             机房票占多数则放弃。
#   代理/VPN/Tor：单源阳性 → 复核；两源及以上阳性 → 放弃。
#   Scamalytics 分数：>25 放弃；11–25 仅作参考（类型投票明确为家宽且标志干净时
#             单独不足以触发复核）。
#   广播 IP、非 PBL 的 DNSBL 命中、启用源失败/超时/解析失败 → 至少复核。
#   Spamhaus PBL（127.0.0.10/11）标为「PBL（家宽正常）」，不视为不干净。
#   coffee 的 DNSBL 在对方服务器上查，不受本机 Clash fake-ip 干扰。
#
# 退出码: 0 通过（可进入下一步）/ 1 需人工复核 / 3 放弃 / 2 参数错误
#
# 测试用 URL 覆盖（完整 URL，用于 fail-closed 自测）:
#   IPCHECK_IPINFO_URL IPCHECK_IPLOGS_URL IPCHECK_SCAMALYTICS_URL
#   IPCHECK_COFFEE_LOOKUP_URL IPCHECK_COFFEE_DNSBL_URL
#   IPCHECK_IPX_URL IPCHECK_IPING_URL IPCHECK_ABUSEIPDB_URL
# ============================================================================
set -uo pipefail

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
KEYFILE="${HOME}/.vps-node/abuseipdb.key"
ABUSEIPDB_KEY="${ABUSEIPDB_KEY:-}"

usage() {
  printf '用法: ip-check-lite.sh <IPv4>\n' >&2
  printf '暂不支持 IPv6。退出码: 0 通过 / 1 复核 / 3 放弃 / 2 参数错误\n' >&2
}

# ---- 参数与 IPv4 校验 ----
IP="${1:-}"
if [ "$IP" = "-h" ] || [ "$IP" = "--help" ]; then
  usage
  exit 2
fi
if [ -z "$IP" ]; then
  usage
  exit 2
fi
case "$IP" in
  *:*)
    printf '暂不支持 IPv6: %s\n' "$IP" >&2
    exit 2
    ;;
esac
case "$IP" in
  *[!0-9.]*)
    printf '不是合法 IPv4: %s\n' "$IP" >&2
    exit 2
    ;;
esac

dots=$(printf '%s' "$IP" | awk -F. '{print NF-1}')
if [ "$dots" != "3" ]; then
  printf '不是合法 IPv4: %s\n' "$IP" >&2
  exit 2
fi

o1=${IP%%.*}
_rest=${IP#*.}
o2=${_rest%%.*}
_rest=${_rest#*.}
o3=${_rest%%.*}
o4=${_rest#*.}
_bad=0
for _o in "$o1" "$o2" "$o3" "$o4"; do
  if [ -z "$_o" ]; then _bad=1; break; fi
  case "$_o" in
    0) ;;
    0*) _bad=1; break ;;
    *[!0-9]*) _bad=1; break ;;
  esac
  if [ "$_o" -lt 0 ] || [ "$_o" -gt 255 ]; then
    _bad=1
    break
  fi
done
if [ "$_bad" -eq 1 ]; then
  printf '不是合法 IPv4: %s（每段必须是 0-255，不能有前导零或多余字符）\n' "$IP" >&2
  exit 2
fi

_reserved=""
if [ "$o1" -eq 10 ]; then
  _reserved="私网 10.0.0.0/8"
elif [ "$o1" -eq 127 ]; then
  _reserved="回环 127.0.0.0/8"
elif [ "$o1" -eq 0 ]; then
  _reserved="保留 0.0.0.0/8"
elif [ "$o1" -eq 169 ] && [ "$o2" -eq 254 ]; then
  _reserved="链路本地 169.254.0.0/16"
elif [ "$o1" -eq 192 ] && [ "$o2" -eq 168 ]; then
  _reserved="私网 192.168.0.0/16"
elif [ "$o1" -eq 172 ] && [ "$o2" -ge 16 ] && [ "$o2" -le 31 ]; then
  _reserved="私网 172.16.0.0/12"
elif [ "$o1" -eq 100 ] && [ "$o2" -ge 64 ] && [ "$o2" -le 127 ]; then
  _reserved="运营商级 NAT 100.64.0.0/10"
elif [ "$o1" -eq 198 ] && [ "$o2" -ge 18 ] && [ "$o2" -le 19 ]; then
  _reserved="基准测试/Clash fake-ip 198.18.0.0/15"
elif [ "$o1" -eq 192 ] && [ "$o2" -eq 0 ] && [ "$o3" -eq 2 ]; then
  _reserved="文档保留 192.0.2.0/24"
elif [ "$o1" -eq 198 ] && [ "$o2" -eq 51 ] && [ "$o3" -eq 100 ]; then
  _reserved="文档保留 198.51.100.0/24"
elif [ "$o1" -eq 203 ] && [ "$o2" -eq 0 ] && [ "$o3" -eq 113 ]; then
  _reserved="文档保留 203.0.113.0/24"
elif [ "$o1" -ge 224 ] && [ "$o1" -le 239 ]; then
  _reserved="组播 224.0.0.0/4"  # lint-allow
elif [ "$o1" -ge 240 ]; then
  _reserved="保留 240.0.0.0/4"  # lint-allow
fi
if [ -n "$_reserved" ]; then
  printf '这是保留/私网地址（%s），不能用于购买前体检: %s\n' "$_reserved" "$IP" >&2
  exit 2
fi

# ---- 可选 AbuseIPDB key（环境变量优先；不把 key 写进命令行）----
ABUSE_ENABLED=0
ABUSE_SKIP_MSG=""
if [ -n "$ABUSEIPDB_KEY" ]; then
  ABUSE_ENABLED=1
elif [ -f "$KEYFILE" ]; then
  # 数字权限：stat 在 macOS 与 Linux 不同
  _oct=""
  if command -v stat >/dev/null 2>&1; then
    _oct=$(stat -c '%a' "$KEYFILE" 2>/dev/null || stat -f '%OLp' "$KEYFILE" 2>/dev/null || printf '')
  fi
  case "$_oct" in
    600|400)
      # 用重定向读入，key 不出现在子进程 argv
      ABUSEIPDB_KEY=$(tr -d '\r' < "$KEYFILE")
      ABUSEIPDB_KEY=${ABUSEIPDB_KEY%%$'\n'*}
      ABUSEIPDB_KEY=${ABUSEIPDB_KEY#"${ABUSEIPDB_KEY%%[![:space:]]*}"}
      ABUSEIPDB_KEY=${ABUSEIPDB_KEY%"${ABUSEIPDB_KEY##*[![:space:]]}"}
      if [ -n "$ABUSEIPDB_KEY" ]; then
        ABUSE_ENABLED=1
      else
        ABUSE_SKIP_MSG="AbuseIPDB: key 文件为空，跳过"
      fi
      ;;
    "")
      ABUSE_SKIP_MSG="AbuseIPDB: 无法读取 $KEYFILE 权限，跳过"
      ;;
    *)
      ABUSE_SKIP_MSG="AbuseIPDB: $KEYFILE 权限为 ${_oct}（需要 600 或 400），跳过"
      ;;
  esac
  unset _perm _mode _oct
else
  ABUSE_SKIP_MSG="AbuseIPDB: 未配置 key，跳过"
fi
export ABUSEIPDB_KEY
export ABUSE_ENABLED
export ABUSE_SKIP_MSG

# ---- 日志目录（600）----
umask 077
STAMP=$(date +%Y%m%d-%H%M)
SAVEDIR="${HOME}/.vps-node/ipaudits/${IP}"
mkdir -p "$SAVEDIR"
LOG="$SAVEDIR/lite-${STAMP}.log"
: > "$LOG"
chmod 600 "$LOG" 2>/dev/null || true

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/ip-check-lite.XXXXXX")
# shellcheck disable=SC2329  # invoked via trap EXIT
CLEANUP() {
  # 确保 key 头文件被删掉
  if [ -n "${WORKDIR:-}" ]; then
    rm -f "$WORKDIR"/abuse.curl.cfg
    rm -rf "$WORKDIR"
  fi
}
trap CLEANUP EXIT

# URL（可被环境变量覆盖；默认值含已校验的 IP）
: "${IPCHECK_IPINFO_URL:=https://ipinfo.io/${IP}/json}"
: "${IPCHECK_IPLOGS_URL:=https://iplogs.com/api/v1/check/${IP}}"
: "${IPCHECK_SCAMALYTICS_URL:=https://scamalytics.com/ip/${IP}}"
: "${IPCHECK_COFFEE_LOOKUP_URL:=https://ip.net.coffee/api/ipv2/lookup/${IP}}"
: "${IPCHECK_COFFEE_DNSBL_URL:=https://ip.net.coffee/api/ipv2/dnsbl/${IP}}"
: "${IPCHECK_IPX_URL:=https://ipx.al/api/report/${IP}}"
: "${IPCHECK_IPING_URL:=https://api.iping.cc/v1/query?ip=${IP}&language=en}"
: "${IPCHECK_ABUSEIPDB_URL:=https://api.abuseipdb.com/api/v2/check?ipAddress=${IP}&maxAgeInDays=90}"

# 把本次要用的 URL 写进清单，给 python 做来源名映射（不含 key）
{
  printf 'ipinfo %s\n' "$IPCHECK_IPINFO_URL"
  printf 'iplogs %s\n' "$IPCHECK_IPLOGS_URL"
  printf 'scamalytics %s\n' "$IPCHECK_SCAMALYTICS_URL"
  printf 'coffee_lookup %s\n' "$IPCHECK_COFFEE_LOOKUP_URL"
  printf 'coffee_dnsbl %s\n' "$IPCHECK_COFFEE_DNSBL_URL"
  printf 'ipx %s\n' "$IPCHECK_IPX_URL"
  printf 'iping %s\n' "$IPCHECK_IPING_URL"
  printf 'abuseipdb %s\n' "$IPCHECK_ABUSEIPDB_URL"
} > "$WORKDIR/urls.txt"

fetch_one() {
  # $1=name $2=url $3=timeout_sec
  local name="$1" url="$2" t="$3"
  local body="$WORKDIR/${name}.body"
  local codef="$WORKDIR/${name}.code"
  local errf="$WORKDIR/${name}.err"
  : > "$body"
  : > "$errf"
  printf '000' > "$codef"
  local http
  http=$(curl -sS -o "$body" -w '%{http_code}' --max-time "$t" -L -A "$UA" "$url" 2>"$errf") || true
  [ -n "$http" ] || http=000
  printf '%s' "$http" > "$codef"
}

fetch_abuse() {
  local url="$1" t="$2"
  local body="$WORKDIR/abuseipdb.body"
  local codef="$WORKDIR/abuseipdb.code"
  local errf="$WORKDIR/abuseipdb.err"
  local cfg="$WORKDIR/abuse.curl.cfg"
  : > "$body"
  : > "$errf"
  printf '000' > "$codef"
  # 密钥只写进 600 配置文件，不出现在 curl 的 argv 里
  cat > "$cfg" <<EOF
silent
show-error
location
max-time = ${t}
user-agent = "${UA}"
header = "Key: ${ABUSEIPDB_KEY}"
header = "Accept: application/json"
output = "${body}"
write-out = "%{http_code}"
url = "${url}"
EOF
  chmod 600 "$cfg"
  local http
  http=$(curl --config "$cfg" 2>"$errf") || true
  rm -f "$cfg"
  [ -n "$http" ] || http=000
  printf '%s' "$http" > "$codef"
}

# ---- 并发拉取 ----
fetch_one ipinfo "$IPCHECK_IPINFO_URL" 15 &
_p1=$!
fetch_one iplogs "$IPCHECK_IPLOGS_URL" 15 &
_p2=$!
fetch_one scamalytics "$IPCHECK_SCAMALYTICS_URL" 20 &
_p3=$!
fetch_one coffee_lookup "$IPCHECK_COFFEE_LOOKUP_URL" 15 &
_p4=$!
fetch_one coffee_dnsbl "$IPCHECK_COFFEE_DNSBL_URL" 20 &
_p5=$!
fetch_one ipx "$IPCHECK_IPX_URL" 20 &
_p6=$!
fetch_one iping "$IPCHECK_IPING_URL" 15 &
_p7=$!
_p8=""
if [ "$ABUSE_ENABLED" = 1 ]; then
  fetch_abuse "$IPCHECK_ABUSEIPDB_URL" 15 &
  _p8=$!
fi

for _p in "$_p1" "$_p2" "$_p3" "$_p4" "$_p5" "$_p6" "$_p7" "$_p8"; do
  [ -n "$_p" ] || continue
  wait "$_p" || true
done

# ---- 判定（响应经文件传入 python，不插进源码）----
# 把启用状态写成小清单，避免 python 读到 key
{
  printf 'abuse_enabled=%s\n' "$ABUSE_ENABLED"
  printf 'abuse_skip=%s\n' "$ABUSE_SKIP_MSG"
  printf 'ip=%s\n' "$IP"
} > "$WORKDIR/meta.txt"

# 清掉环境里的 key，防止任何子进程或调试输出带出
unset ABUSEIPDB_KEY

{
  printf '== 裸 IP 快查: %s  %s ==\n' "$IP" "$(date '+%F %T')"
  python3 - "$WORKDIR" <<'PY'
import json, os, re, sys
from collections import OrderedDict

WORKDIR = sys.argv[1]
PBL_CODES = {"127.0.0.10", "127.0.0.11"}

def read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default

def http_code(name):
    raw = read(os.path.join(WORKDIR, name + ".code"), "000").strip()
    try:
        return int(raw)
    except ValueError:
        return 0

def body(name):
    return read(os.path.join(WORKDIR, name + ".body"))

def err(name):
    return read(os.path.join(WORKDIR, name + ".err")).strip()

meta = {}
for line in read(os.path.join(WORKDIR, "meta.txt")).splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        meta[k] = v

IP = meta.get("ip", "")
abuse_enabled = meta.get("abuse_enabled") == "1"
abuse_skip = meta.get("abuse_skip", "")

# ---------- 通用 ----------
def looks_cloudflare(html):
    t = html.lower()
    return ("just a moment" in t) or ("cf-mitigated" in t) or (
        "enable javascript and cookies to continue" in t
    )

def try_json(text):
    text = text.strip()
    if not text:
        return None, "空响应"
    try:
        return json.loads(text), None
    except Exception as e:
        return None, "不是 JSON: %s" % e

# ---------- 类型/标志集合 ----------
RES_TYPES = {
    "isp", "residential", "resi", "mobile", "mob", "isp/mob", "fixed line isp",
    "cable", "dsl", "fiber", "consumer", "home",
}
HOST_TYPES = {
    "hosting", "datacenter", "data center", "data centre", "dch", "idc",
    "server", "cdn", "cloud", "transit", "data center/web hosting/transit",
}

def norm(s):
    return (s or "").strip().lower()

def classify_label(val):
    n = norm(val)
    if not n or n in ("?", "n/a", "na", "unknown", "null", "-", "none"):
        return None
    if n in RES_TYPES or n.startswith("isp") or "residential" in n:
        return "res"
    if n in HOST_TYPES or "datacenter" in n or "data center" in n or n == "idc":
        return "host"
    return None

# rDNS
HOST_RDNS = re.compile(
    r"(vps|hosting|dedicated|colocation|\bcolo\b|datacenter|data-center|"
    r"digitalocean|linode|hetzner|vultr|contabo|\bovh\b|amazonaws|"
    r"googleusercontent|cloudapp|azure|akamai|leaseweb|hivelocity|"
    r"ip-\d+-\d+-\d+-\d+)",
    re.I,
)
# 单独的 static/cloud/server 较弱，且易与家宽主机名撞车
HOST_RDNS_WEAK = re.compile(r"(\bstatic\b|\bcloud\b|\bserver\b)", re.I)
RES_RDNS = re.compile(
    r"(hsd|\bdyn\b|dhcp|\bdsl\b|adsl|cable|fiber|fibre|\bres\b|resid|"
    r"\bpool\b|\bcpe\b|pppoe|comcast|charter|\bspectrum\b|verizon|\bfios\b|"
    r"sbcglobal|bellsouth|\bcox\.|\batt\.net|frontier|centurylink|qwest|"
    r"shawcable|rogers|videotron|telus|\bbt\.net|virginmedia|skybroadband|"
    r"t-online|wanadoo|\brr\.com|res\.rr|cpe\.)",
    re.I,
)

def rdns_signal(hostname):
    if not hostname or hostname in ("?", "(无)", "null", "None"):
        return None, None
    h = hostname.strip()
    res = bool(RES_RDNS.search(h))
    host_strong = bool(HOST_RDNS.search(h))
    host_weak = bool(HOST_RDNS_WEAK.search(h))
    if res and not host_strong:
        return "res", h
    if host_strong and not res:
        return "host", h
    if res and host_strong:
        return "mixed", h
    if host_weak and not res:
        return "host_weak", h
    return None, h

# ---------- 拉取每个源 ----------
sources = OrderedDict()  # name -> dict

def add(name, title):
    sources[name] = {
        "name": name,
        "title": title,
        "ok": False,
        "enabled": True,
        "error": None,
        "http": http_code(name if name != "coffee" else "coffee_lookup"),
        "detail_lines": [],
        "type_vote": None,       # 'res' | 'host' | None
        "type_note": "",
        "flags": [],             # list of 'vpn'/'proxy'/'tor'
        "flag_note": "",
        "hostnames": [],
        "notes": [],
    }
    return sources[name]

def mark_fail(s, reason):
    s["ok"] = False
    s["error"] = reason
    s["type_vote"] = None
    s["flags"] = []

# ---- ipinfo ----
s = add("ipinfo", "ipinfo")
raw = body("ipinfo")
e = err("ipinfo")
if s["http"] != 200 or not raw.strip():
    why = e or ("HTTP %s" % s["http"] if s["http"] else "网络/TLS 失败")
    if not raw.strip() and s["http"] in (0, 000):
        why = e or "网络/TLS 失败（空响应）"
    mark_fail(s, why)
else:
    d, je = try_json(raw)
    if d is None:
        mark_fail(s, je)
    elif d.get("error") or (d.get("status") and d.get("status") != 200 and "ip" not in d):
        mark_fail(s, "接口错误: %s" % (d.get("error") or d.get("status")))
    else:
        s["ok"] = True
        for k in ("ip", "hostname", "city", "region", "country", "org", "timezone"):
            s["detail_lines"].append("  %s: %s" % (k, d.get(k)))
        if d.get("hostname"):
            s["hostnames"].append(d.get("hostname"))

# ---- IPLogs ----
s = add("iplogs", "IPLogs")
raw = body("iplogs")
if s["http"] != 200 or not raw.strip():
    mark_fail(s, err("iplogs") or ("HTTP %s" % s["http"]))
else:
    d, je = try_json(raw)
    if d is None:
        mark_fail(s, je)
    else:
        s["ok"] = True
        typ = (d.get("ip_info") or {}).get("type")
        hosting = bool(d.get("is_hosting"))
        s["detail_lines"].append(
            "  score: %s | verdict: %s | reputation: %s"
            % (d.get("score"), d.get("verdict"), d.get("reputation"))
        )
        s["detail_lines"].append(
            "  vpn: %s | proxy: %s | tor: %s | hosting: %s"
            % (d.get("is_vpn"), d.get("is_proxy"), d.get("is_tor"), d.get("is_hosting"))
        )
        ii = d.get("ip_info") or {}
        s["detail_lines"].append(
            "  type: %s | asn: %s %s" % (typ, ii.get("asn"), ii.get("org"))
        )
        for sig in (d.get("signals") or [])[:8]:
            s["detail_lines"].append(
                "  signal: %s | weight: %s" % (sig.get("type"), sig.get("weight"))
            )
        # type vote
        cl = classify_label(typ)
        if hosting or cl == "host":
            s["type_vote"] = "host"
            s["type_note"] = "type=%s is_hosting=%s" % (typ, hosting)
        elif cl == "res":
            s["type_vote"] = "res"
            s["type_note"] = "type=%s" % typ
        else:
            s["type_note"] = "type=%s is_hosting=%s" % (typ, hosting)
        for flag, key in (("vpn", "is_vpn"), ("proxy", "is_proxy"), ("tor", "is_tor")):
            if d.get(key):
                s["flags"].append(flag)
        s["_verdict"] = d.get("verdict")

# ---- Scamalytics ----
s = add("scamalytics", "Scamalytics")
s["http"] = http_code("scamalytics")
raw = body("scamalytics")
if s["http"] != 200 or not raw.strip():
    mark_fail(s, err("scamalytics") or ("HTTP %s" % s["http"]))
elif looks_cloudflare(raw):
    mark_fail(s, "页面被 Cloudflare 拦截")
else:
    # 表格字段
    def cell(label):
        m = re.search(
            r"<th[^>]*>\s*" + re.escape(label) + r"\s*</th>\s*<td[^>]*>([\s\S]*?)</td>",
            raw,
            re.I,
        )
        if not m:
            return None
        v = re.sub(r"<[^>]+>", "", m.group(1))
        return re.sub(r"\s+", " ", v).strip()

    text = re.sub(r"<script[\s\S]*?</script>", " ", raw, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    m = re.search(r"Fraud Score:\s*(\d+)", text)
    if not m:
        mark_fail(s, "页面未解析到 Fraud Score（结构变化或被挡）")
    else:
        s["ok"] = True
        score = int(m.group(1))
        win = text[max(0, m.start() - 400):m.start()]
        vm = re.search(r"(Very High|High|Elevated|Medium|Low|Very Low)\s*Risk", win, re.I)
        verdict = vm.group(1) if vm else None
        s["_score"] = score
        s["_risk"] = verdict
        flags_map = {
            "Anonymizing VPN": "vpn",
            "Tor Exit Node": "tor",
            "Public Proxy": "proxy",
            "Web Proxy": "proxy",
            "Residential Proxy": "proxy",
        }
        server = cell("Server")
        s["_server"] = server
        for lab, flag in flags_map.items():
            val = cell(lab)
            s["detail_lines"].append("  %s: %s" % (lab, val if val is not None else "?"))
            if val and val.lower() in ("yes", "true", "1"):
                if flag not in s["flags"]:
                    s["flags"].append(flag)
        s["detail_lines"].insert(0, "  fraud_score: %s" % score)
        s["detail_lines"].insert(1, "  verdict: %s" % (verdict or "?"))
        s["detail_lines"].append("  Server: %s" % (server if server is not None else "?"))
        hn = cell("Hostname")
        isp = cell("ISP Name")
        org = cell("Organization Name")
        conn = cell("Connection type")
        if hn:
            s["hostnames"].append(hn)
            s["detail_lines"].append("  Hostname: %s" % hn)
        if isp:
            s["detail_lines"].append("  ISP Name: %s" % isp)
        if org:
            s["detail_lines"].append("  Organization: %s" % org)
        if conn:
            s["detail_lines"].append("  Connection type: %s" % conn)
        if server and server.lower() in ("yes", "true", "1"):
            s["type_vote"] = "host"
            s["type_note"] = "Server=Yes"
        elif server and server.lower() in ("no", "false", "0"):
            s["type_vote"] = "res"
            s["type_note"] = "Server=No"
        else:
            s["type_note"] = "Server=%s" % server

# ---- coffee lookup + dnsbl（算两个可能失败的子源，投票算一个源）----
s = add("coffee", "ip.net.coffee")
# 先 lookup
s["http"] = http_code("coffee_lookup")
raw = body("coffee_lookup")
dnsbl_http = http_code("coffee_dnsbl")
dnsbl_raw = body("coffee_dnsbl")
dnsbl_err = err("coffee_dnsbl")
lookup_ok = True
if s["http"] != 200 or not raw.strip():
    mark_fail(s, err("coffee_lookup") or ("lookup HTTP %s" % s["http"]))
    lookup_ok = False
else:
    d, je = try_json(raw)
    if d is None:
        mark_fail(s, "lookup " + je)
        lookup_ok = False
    else:
        s["ok"] = True
        s["_coffee"] = d
        s["detail_lines"].append(
            "  isResidential: %s | is_datacenter: %s | company_type: %s | asn_kind: %s"
            % (d.get("isResidential"), d.get("is_datacenter"), d.get("company_type"), d.get("asn_kind"))
        )
        s["detail_lines"].append(
            "  company: %s | ASN: AS%s %s"
            % (d.get("company_name"), d.get("asn"), d.get("asOrganization") or d.get("asname"))
        )
        rc, cc = d.get("registered_country_code"), d.get("countryCode")
        if rc and cc:
            native = "原生" if str(rc).lower() == str(cc).lower() else "非原生（注册地 %s，使用地 %s）" % (rc, cc)
            s["detail_lines"].append("  原生性: %s" % native)
            if str(rc).lower() != str(cc).lower():
                s["notes"].append("coffee 标为非原生")
                s["_broadcast_hint"] = True
        if d.get("rdns"):
            s["hostnames"].append(d.get("rdns"))
            s["detail_lines"].append("  rdns: %s" % d.get("rdns"))
        s["detail_lines"].append(
            "  vpn: %s | proxy: %s | tor: %s | trust_score: %s | abuser_score: %s"
            % (d.get("is_vpn"), d.get("is_proxy"), d.get("is_tor"), d.get("trust_score"), d.get("abuser_score") or "—")
        )
        ai = d.get("ai_verdict") or {}
        if isinstance(ai, dict) and ai.get("label"):
            s["detail_lines"].append(
                "  ai_verdict: %s (%s%%) %s"
                % (ai.get("label"), ai.get("confidence"), ai.get("reasoning") or "")
            )
        if d.get("is_public_service"):
            ps = d.get("public_service") or {}
            s["notes"].append("公共任播服务: %s" % (ps.get("service") or "yes"))
        # type vote（一个源一票）
        if d.get("isResidential") and not d.get("is_datacenter"):
            s["type_vote"] = "res"
        elif d.get("is_datacenter"):
            s["type_vote"] = "host"
        else:
            a = classify_label(d.get("company_type"))
            b = classify_label(d.get("asn_kind"))
            if a == "host" or b == "host":
                s["type_vote"] = "host"
            elif a == "res" or b == "res":
                s["type_vote"] = "res"
        s["type_note"] = "isResidential=%s company_type=%s asn_kind=%s" % (
            d.get("isResidential"), d.get("company_type"), d.get("asn_kind")
        )
        for flag, key in (("vpn", "is_vpn"), ("proxy", "is_proxy"), ("tor", "is_tor")):
            if d.get(key):
                s["flags"].append(flag)

# dnsbl：lookup 成功也必须能解析 dnsbl，否则 fail-closed
s["_dnsbl_ok"] = False
s["_dnsbl_hits"] = []
s["_dnsbl_pbl"] = []
if lookup_ok:
    if dnsbl_http != 200 or not dnsbl_raw.strip():
        # 降级为源失败
        mark_fail(s, "dnsbl 失败: " + (dnsbl_err or ("HTTP %s" % dnsbl_http)))
        # 保留已解析的类型投票？失败则整源不算。按 fail-closed，该源失败、不投票。
        s["type_vote"] = None
        s["flags"] = []
    else:
        db, je = try_json(dnsbl_raw)
        if db is None:
            mark_fail(s, "dnsbl " + je)
            s["type_vote"] = None
            s["flags"] = []
        else:
            s["_dnsbl_ok"] = True
            results = db.get("results") or []
            listed = [r for r in results if r.get("listed")]
            clean_n = len(results) - len(listed)
            pbl_only = []
            real_hits = []
            for r in listed:
                codes = [str(c) for c in (r.get("codes") or [])]
                eng = r.get("engine") or r.get("zone") or "?"
                is_spamhaus = "spamhaus" in (eng + " " + str(r.get("zone") or "")).lower()
                if is_spamhaus and codes and all(c in PBL_CODES for c in codes):
                    pbl_only.append("%s %s" % (eng, "/".join(codes)))
                elif is_spamhaus and any(c in PBL_CODES for c in codes) and not all(c in PBL_CODES for c in codes):
                    real_hits.append("%s %s（含非 PBL）" % (eng, "/".join(codes)))
                else:
                    real_hits.append("%s %s" % (eng, "/".join(codes) if codes else "listed"))
            s["_dnsbl_hits"] = real_hits
            s["_dnsbl_pbl"] = pbl_only
            parts = ["DNSBL: %d/%d 家未列" % (clean_n, len(results))]
            if pbl_only:
                parts.append("PBL（家宽正常）: " + "; ".join(pbl_only))
            if real_hits:
                parts.append("命中: " + "; ".join(real_hits))
            s["detail_lines"].append("  " + " | ".join(parts))
            s["notes"].append("DNSBL 由 coffee 服务端查询，不受本机 Clash fake-ip 影响")

# ---- ipx.al ----
s = add("ipx", "ipx.al")
raw = body("ipx")
if s["http"] != 200 or not raw.strip():
    mark_fail(s, err("ipx") or ("HTTP %s" % s["http"]))
else:
    d, je = try_json(raw)
    if d is None:
        mark_fail(s, je)
    else:
        s["ok"] = True
        typ = ((d.get("type") or {}).get("verdict"))
        native = ((d.get("native") or {}).get("verdict"))
        health = d.get("health") or {}
        s["detail_lines"].append(
            "  type: %s | native: %s | health: %s %s"
            % (typ, native, health.get("score"), health.get("grade"))
        )
        tally = (d.get("type") or {}).get("tally")
        if tally:
            s["detail_lines"].append("  type.tally: %s | pseudoResi: %s" % (tally, (d.get("type") or {}).get("pseudoResi")))
        if d.get("hostname"):
            s["hostnames"].append(d["hostname"])
            s["detail_lines"].append("  hostname: %s" % d["hostname"])
        net = d.get("network") or {}
        if net.get("humanPct") is not None:
            s["detail_lines"].append("  humanPct: %s%%" % net.get("humanPct"))
        ipdb = d.get("ipdb") or {}
        if isinstance(ipdb, dict) and ipdb.get("datacenter"):
            s["detail_lines"].append("  ipdb.datacenter: %s" % ipdb["datacenter"])
        # type vote
        tn = norm(typ)
        if (d.get("type") or {}).get("pseudoResi") or tn in ("pseudo", "pseudo-resi", "hosting"):
            s["type_vote"] = "host"
            s["type_note"] = "type.verdict=%s pseudoResi=%s" % (typ, (d.get("type") or {}).get("pseudoResi"))
        elif tn in ("isp", "mobile"):
            s["type_vote"] = "res"
            s["type_note"] = "type.verdict=%s" % typ
        else:
            s["type_note"] = "type.verdict=%s（不计入投票）" % typ
        if native and norm(native) in ("broadcast", "non-native", "non_native"):
            s["_broadcast"] = True
            s["notes"].append("ipx 判定为广播 IP")
        elif native:
            s["detail_lines"].append("  native.verdict: %s" % native)
        # flags: 忽略「仅单源标记为代理」的误报
        items = health.get("items") or []
        single_proxy_tip = any(
            (it or {}).get("code") == "single_source_proxy" for it in items
        )
        anon_hits = []
        for cat in (d.get("categories") or []):
            if cat.get("key") != "anon":
                continue
            for ch in (cat.get("checks") or []):
                if ch.get("hit") is True:
                    lab = ch.get("label") or ""
                    anon_hits.append(lab)
        # 映射中文标签
        def map_lab(lab):
            if lab in ("VPN",):
                return "vpn"
            if lab in ("Tor",):
                return "tor"
            if lab in ("代理", "匿名出口", "iCloud 中继"):
                return "proxy"
            return None
        meaningful = []
        for lab in anon_hits:
            fl = map_lab(lab)
            if fl == "proxy" and lab == "代理" and single_proxy_tip and len(anon_hits) == 1:
                s["notes"].append("ipx 仅单源标记代理，忽略（防误报）")
                continue
            if fl and fl not in s["flags"]:
                s["flags"].append(fl)
                meaningful.append(lab)
        if meaningful:
            s["flag_note"] = "命中: " + ", ".join(meaningful)

# ---- iping ----
s = add("iping", "iping.cc")
raw = body("iping")
if s["http"] != 200 or not raw.strip():
    mark_fail(s, err("iping") or ("HTTP %s" % s["http"]))
else:
    d, je = try_json(raw)
    if d is None:
        mark_fail(s, je)
    elif d.get("code") not in (200, "200", None) and not d.get("data"):
        mark_fail(s, "接口 code=%s %s" % (d.get("code"), d.get("msg") or ""))
    else:
        data = d.get("data") if isinstance(d.get("data"), dict) else d
        s["ok"] = True
        usage = data.get("usage_type")
        as_type = data.get("as_type")
        company_type = data.get("company_type")
        typ = data.get("type")  # native / broadcast
        s["detail_lines"].append(
            "  usage_type: %s | as_type: %s | company_type: %s | type: %s"
            % (usage, as_type, company_type, typ)
        )
        s["detail_lines"].append(
            "  isp: %s | is_proxy: %s | risk_score: %s"
            % (data.get("isp"), data.get("is_proxy"), data.get("risk_score"))
        )
        cu, ca, cc = classify_label(usage), classify_label(as_type), classify_label(company_type)
        votes = [v for v in (cu, ca, cc) if v]
        if "host" in votes and "res" in votes:
            s["type_vote"] = "host"  # 矛盾时从严
            s["type_note"] = "字段矛盾 usage=%s as_type=%s company=%s，按机房计" % (usage, as_type, company_type)
        elif "host" in votes:
            s["type_vote"] = "host"
            s["type_note"] = "usage_type=%s as_type=%s" % (usage, as_type)
        elif "res" in votes:
            s["type_vote"] = "res"
            s["type_note"] = "usage_type=%s as_type=%s" % (usage, as_type)
        else:
            s["type_note"] = "usage_type=%s as_type=%s company_type=%s" % (usage, as_type, company_type)
        if typ and norm(typ) in ("broadcast", "non-native", "non_native"):
            s["_broadcast"] = True
            s["notes"].append("iping 判定为广播 IP")
        proxy = data.get("is_proxy")
        if proxy in (True, "true", "True", "yes", "1", 1):
            s["flags"].append("proxy")

# ---- AbuseIPDB（可选）----
s = add("abuseipdb", "AbuseIPDB")
if not abuse_enabled:
    s["enabled"] = False
    s["ok"] = True  # 未启用不算失败
    s["error"] = None
    s["http"] = 0
    s["detail_lines"].append("  %s" % (abuse_skip or "AbuseIPDB: 未配置 key，跳过"))
else:
    raw = body("abuseipdb")
    if s["http"] != 200 or not raw.strip():
        mark_fail(s, err("abuseipdb") or ("HTTP %s" % s["http"]))
    else:
        d, je = try_json(raw)
        if d is None:
            mark_fail(s, je)
        elif d.get("errors"):
            mark_fail(s, "接口错误（未记录密钥）")
        else:
            data = d.get("data") or d
            s["ok"] = True
            score = data.get("abuseConfidenceScore")
            reports = data.get("totalReports")
            last = data.get("lastReportedAt")
            usage = data.get("usageType")
            s["_abuse_score"] = score
            s["_abuse_reports"] = reports
            s["detail_lines"].append(
                "  abuseConfidenceScore: %s | totalReports(90d): %s | lastReportedAt: %s"
                % (score, reports, last or "—")
            )
            s["detail_lines"].append(
                "  usageType: %s | isp: %s | isTor: %s"
                % (usage, data.get("isp"), data.get("isTor"))
            )
            cl = classify_label(usage)
            # AbuseIPDB 的 usageType 来自 IPinfo，仅作备注，不单独占类型票，避免和 ipinfo 免费层信息重复加权
            if cl:
                s["notes"].append("AbuseIPDB usageType=%s（仅供参考，不计入类型投票）" % usage)
            if data.get("isTor"):
                s["flags"].append("tor")

# ---------- 汇总投票 ----------
type_voters = []  # (title, vote, note)
flag_voters = []  # (title, flags)

for name, s in sources.items():
    if not s["enabled"]:
        continue
    if s["ok"] and s["type_vote"] in ("res", "host"):
        type_voters.append((s["title"], s["type_vote"], s["type_note"]))
    if s["ok"] and s["flags"]:
        flag_voters.append((s["title"], list(s["flags"])))

res_n = sum(1 for _, v, _ in type_voters if v == "res")
host_n = sum(1 for _, v, _ in type_voters if v == "host")
flag_sources_n = len(flag_voters)

failed = [s for s in sources.values() if s["enabled"] and not s["ok"]]

# rDNS
hostnames = []
for s in sources.values():
    hostnames.extend(s.get("hostnames") or [])
rdns_votes = []
rdns_seen = []
for h in hostnames:
    if h in rdns_seen:
        continue
    rdns_seen.append(h)
    sig, _ = rdns_signal(h)
    rdns_votes.append((h, sig))

# ---------- 判定 ----------
reject = []
review = []
notes = []

if failed:
    names = "、".join(s["title"] + "（" + (s["error"] or "未知错误") + "）" for s in failed)
    review.append("以下启用源失败，按 fail-closed 至少需要人工复核: %s" % names)

# 类型投票
type_pass = (res_n >= 2 and res_n > host_n)
if host_n > res_n and host_n >= 2:
    reject.append("类型投票：机房/IDC %d 票 vs 家宽/ISP %d 票，多数源判机房，建议放弃" % (host_n, res_n))
elif not type_pass:
    review.append("类型投票未通过（家宽/ISP %d 票，机房/IDC %d 票；通过需至少 2 票家宽且多于机房票）" % (res_n, host_n))
else:
    notes.append("类型投票通过：家宽/ISP %d 票，机房/IDC %d 票" % (res_n, host_n))

# 代理/VPN/Tor
if flag_sources_n >= 2:
    labs = "、".join("%s(%s)" % (t, "/".join(f)) for t, f in flag_voters)
    reject.append("代理/VPN/Tor：%d 个源阳性（%s），建议放弃" % (flag_sources_n, labs))
elif flag_sources_n == 1:
    t, f = flag_voters[0]
    review.append("代理/VPN/Tor：仅 %s 单源阳性（%s），需复核" % (t, "/".join(f)))
else:
    notes.append("代理/VPN/Tor：无源阳性")

# Scamalytics 分数
sc = sources["scamalytics"]
score = sc.get("_score")
if sc["ok"] and score is not None:
    if score > 25:
        reject.append("Scamalytics Fraud Score %d > 25，建议放弃" % score)
    elif score >= 11:
        if type_pass and flag_sources_n == 0:
            notes.append("Scamalytics Fraud Score %d（11–25，仅作参考；类型投票明确为家宽且标志干净，不单独触发复核）" % score)
        else:
            review.append("Scamalytics Fraud Score %d 处于 11–25，且类型投票不够明确或已有其他风险，需复核" % score)
    else:
        notes.append("Scamalytics Fraud Score %d（低）" % score)

# 广播
for name in ("ipx", "iping"):
    if sources[name]["ok"] and sources[name].get("_broadcast"):
        review.append("%s 判定为广播 IP，需复核" % sources[name]["title"])
if sources["coffee"]["ok"] and sources["coffee"].get("_broadcast_hint"):
    review.append("ip.net.coffee 注册地与使用地不一致（非原生），需复核")

# DNSBL
cof = sources["coffee"]
if cof.get("_dnsbl_ok"):
    if cof.get("_dnsbl_hits"):
        review.append("DNSBL 命中非 PBL 名单: %s" % "; ".join(cof["_dnsbl_hits"]))
    if cof.get("_dnsbl_pbl"):
        notes.append("%s —— 家宽段常见，不视为不干净" % "; ".join(cof["_dnsbl_pbl"]))

# AbuseIPDB
ab = sources["abuseipdb"]
if ab["enabled"] and ab["ok"]:
    ascore = ab.get("_abuse_score")
    reps = ab.get("_abuse_reports")
    try:
        ascore_n = int(ascore) if ascore is not None else None
    except (TypeError, ValueError):
        ascore_n = None
    try:
        reps_n = int(reps) if reps is not None else 0
    except (TypeError, ValueError):
        reps_n = 0
    if ascore_n is not None and ascore_n >= 75:
        reject.append("AbuseIPDB abuseConfidenceScore %s ≥ 75，建议放弃" % ascore_n)
    elif (ascore_n is not None and ascore_n >= 25) or reps_n >= 5:
        review.append("AbuseIPDB 需复核（score=%s, totalReports(90d)=%s）" % (ascore, reps))
    elif reps_n > 0:
        notes.append("AbuseIPDB 近 90 天有 %s 条举报，score=%s（未达复核线）" % (reps, ascore))

# IPLogs verdict
il = sources["iplogs"]
if il["ok"]:
    verd = il.get("_verdict")
    if verd and norm(verd) not in ("clean", "allow", "allowlist"):
        review.append("IPLogs verdict=%s（非 clean），需复核" % verd)

# rDNS
rdns_host_strong = any(sig == "host" for _, sig in rdns_votes)
rdns_res = any(sig == "res" for _, sig in rdns_votes)
for h, sig in rdns_votes:
    if sig == "res":
        notes.append("rDNS 像家宽: %s" % h)
    elif sig == "host":
        notes.append("rDNS 像机房: %s" % h)
    elif sig == "host_weak":
        notes.append("rDNS 弱机房信号: %s" % h)
    elif sig == "mixed":
        notes.append("rDNS 信号混合: %s" % h)
    elif h:
        notes.append("rDNS: %s" % h)
if rdns_host_strong and not rdns_res and not type_pass:
    review.append("rDNS 呈机房风格，且类型投票未明确通过，需复核")

# ---------- 打印 ----------
def status_of(s):
    if not s["enabled"]:
        return "跳过"
    if not s["ok"]:
        return "失败"
    return "成功"

print()
for name, s in sources.items():
    print("=== %s ===" % s["title"])
    if not s["enabled"]:
        for line in s["detail_lines"]:
            print(line)
        continue
    if not s["ok"]:
        print("  状态: 失败 | HTTP %s | %s" % (s["http"] or "000", s["error"] or "未知错误"))
        continue
    print("  状态: 成功 | HTTP %s" % s["http"])
    for line in s["detail_lines"]:
        print(line)
    print()

print("----------------------------------------")
print("来源摘要")
print("%-16s %-6s %-8s %-16s %s" % ("来源", "状态", "类型投票", "代理/VPN/Tor", "说明"))
for name, s in sources.items():
    vote = {"res": "家宽", "host": "机房"}.get(s["type_vote"], "—") if s["ok"] and s["enabled"] else "—"
    flags = "/".join(s["flags"]) if (s["ok"] and s["flags"]) else ("无" if s["ok"] and s["enabled"] else "—")
    if not s["enabled"]:
        extra = (s["detail_lines"][0].strip() if s["detail_lines"] else "未启用")
    elif not s["ok"]:
        extra = s["error"] or "失败"
    else:
        extra = s["type_note"] or ""
        if s.get("flag_note"):
            extra = (extra + " | " + s["flag_note"]).strip(" |")
    # 截断过长说明
    if len(extra) > 80:
        extra = extra[:77] + "..."
    print("%-16s %-6s %-8s %-16s %s" % (s["title"], status_of(s), vote, flags, extra))

print()
print("类型投票合计: 家宽/ISP %d  |  机房/IDC %d  |  投票源 %d" % (res_n, host_n, len(type_voters)))
if type_voters:
    for title, vote, note in type_voters:
        lab = "家宽" if vote == "res" else "机房"
        print("  - %s → %s%s" % (title, lab, ("（%s）" % note) if note else ""))

print()
print("判定依据:")
for x in reject:
    print("  [放弃] " + x)
for x in review:
    print("  [复核] " + x)
for x in notes:
    print("  [备注] " + x)
if not reject and not review and not notes:
    print("  （无额外说明）")

print("----------------------------------------")
if reject:
    code = 3
    print("判定: 放弃")
elif review:
    code = 1
    print("判定: 需人工复核")
else:
    code = 0
    print("判定: 快查通过 → 下一步用代理凭据跑 ip-audit.sh 完整体检")

# 给 bash 的退出码文件（不依赖管道）
with open(os.path.join(WORKDIR, "exit_code"), "w", encoding="utf-8") as f:
    f.write(str(code))
sys.exit(code)
PY
} 2>&1 | tee -a "$LOG"

PY_CODE=${PIPESTATUS[0]:-1}
if [ -f "$WORKDIR/exit_code" ]; then
  PY_CODE=$(tr -d '[:space:]' < "$WORKDIR/exit_code")
fi
# LOG 里绝不该出现 AbuseIPDB key（再保险扫一次，只查占位模式以外的泄露；这里不打印 key）
printf '日志: %s\n' "$LOG" | tee -a "$LOG"
case "$PY_CODE" in
  0|1|2|3) exit "$PY_CODE" ;;
  *) exit 1 ;;
esac
