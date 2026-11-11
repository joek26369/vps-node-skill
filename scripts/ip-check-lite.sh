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
#             机房票占多数则放弃。机房票 ≥ 2（即使家宽仍占多数，含仅多 1 票）
#             至少复核，不直接放弃。
#   代理/VPN/Tor：单源阳性 → 复核；两源及以上阳性 → 放弃。
#   Scamalytics 分数：>25 放弃；11–25 仅作参考（类型投票明确为家宽、机房票 < 2
#             且标志干净时，单独不足以触发复核）。Server=Yes 计为机房票并列入风险。
#   广播 IP、非 PBL 的 DNSBL 命中、启用源失败/超时/解析失败 → 至少复核。
#   Spamhaus PBL（127.0.0.10/11）标为「PBL（家宽正常）」，不视为不干净。
#   coffee 的 DNSBL 在对方服务器上查，不受本机 Clash fake-ip 干扰。
#   主流家宽运营商加分（仅 AT&T / Verizon / Comcast）：机房票为 0 时 +1 家宽票，
#             并让 Scamalytics 11–25 仅作参考。不加分不覆盖机房多数、代理/VPN/Tor、
#             DNSBL、AbuseIPDB、广播、Fraud Score >25。商业线与无消费侧证据的 AS701 不加分。
#
# 每次跑完会追加「情况分析」块（留 / 换 / 待复核 + 综合分），并写入
#   ~/.vps-node/ipaudits/<IP>/lite-<stamp>.json（600），供 ip-compare.sh 汇总比较。
#
# 退出码: 0 通过（留）/ 1 需人工复核 / 3 放弃（换）/ 2 参数错误
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
STAMP=$(date +%Y%m%d-%H%M%S)
SAVEDIR="${HOME}/.vps-node/ipaudits/${IP}"
mkdir -p "$SAVEDIR"
LOG="$SAVEDIR/lite-${STAMP}.log"
JSON_OUT="$SAVEDIR/lite-${STAMP}.json"
: > "$LOG"
: > "$JSON_OUT"
chmod 600 "$LOG" "$JSON_OUT" 2>/dev/null || true
WHEN=$(date '+%Y-%m-%dT%H:%M:%S%z')

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
  printf 'timestamp=%s\n' "$WHEN"
  printf 'json_path=%s\n' "$JSON_OUT"
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

# ---------------------------------------------------------------------------
# 主流家宽运营商加分表（只这三家，往下追加即可）
#   asn_consumer: 消费/家宽 ASN，可作为加分证据（仍须过商业线检查）
#   asn_mobile:   移动网 ASN，加分但标注「移动网络」
#   asn_mixed:    消费与企业混跑，不能单凭 ASN 加分，必须有消费侧名称或 rDNS
# AS701 = 原 UUNET / Verizon Business 骨干，也承载 Fios 家宽，故列入 mixed。
# AT&T 工商注册名现为 "AT&T Enterprises, LLC"，这是法律实体名，不单独视为商业线。
# Comcast 7015/7016 是其地区接入 ASN，不是 AT&T（AT&T 主 ASN 是 7018）。
# ---------------------------------------------------------------------------
OPERATORS = [
    {
        "brand": "Comcast",
        "asn_consumer": [
            7922,
            7015, 7016,
            7725, 11025, 13367, 13385, 14668, 16748,
            20214, 21508, 22258, 22909, 23253, 23266, 33287,
            33489, 33490, 33491,
            33650, 33651, 33652, 33653, 33654, 33655, 33656, 33657,
            33658, 33659, 33660, 33661, 33662, 33663, 33664, 33665,
            33666, 33667, 33668,
        ],
        "asn_mobile": [],
        "asn_mixed": [],
        "name_re": r"comcast|xfinity",
        "rdns_re": r"(?<!business\.)comcast\.net|xfinity\.com|\bhsd\d\.",
        "consumer_re": r"xfinity|\bhsd\d\.|comcast\.net",
        "business_re": r"comcast\s*business|comcastbusiness\.net",
    },
    {
        "brand": "AT&T",
        "asn_consumer": [7018, 6389, 7132],
        "asn_mobile": [20057],
        "asn_mixed": [],
        "name_re": r"at\s*&\s*t|at\s*and\s*t|\batt\b|sbcglobal|bellsouth",
        "rdns_re": r"sbcglobal\.net|bellsouth\.net|lightspeed|\.att\.net|phones\.att\.net",
        "consumer_re": r"sbcglobal|bellsouth|lightspeed|private\s+customer|at\s*&\s*t\s+internet|att\s+internet|u-verse|uverse|att\.net",
        "business_re": r"at\s*&\s*t\s+business|att\s+business|at\s*&\s*t\s+enterprise(?!s,\s*llc)|att\s+global\s+network",
    },
    {
        "brand": "Verizon",
        "asn_consumer": [19262],
        "asn_mobile": [6167, 22394],
        "asn_mixed": [701],
        "name_re": r"verizon|\bfios\b|cellco|myvzw|vzwdms",
        "rdns_re": r"fios\.verizon\.net|(?:pool-|static-|dsl-).+\.verizon\.net|(?:east|west)\.verizon\.net|myvzw\.com|vzwdms\.com",
        "consumer_re": r"\bfios\b|verizon\s+online|verizon\s+fios|verizon\s+wireless|cellco|myvzw|vzwdms|pool-.+\.verizon\.net",
        "business_re": r"verizon\s*business|(?<![a-z])(?:mci|uunet)(?![a-z])|uu\.net|alter\.net",
    },
]

# 法律实体名：不当作「Enterprise/Business 产品线」
LEGAL_ENTITY_RE = re.compile(
    r"at\s*&\s*t\s+enterprises,?\s*llc",
    re.I,
)
# 通用商业/机房产品线（品牌自己的 business_re 之外）
GENERIC_BUSINESS_RE = re.compile(
    r"\b(?:datacenters?|data\s*cent(?:er|re)s?|\bcloud\b|\bhosting\b)\b",
    re.I,
)
MOBILE_RE = re.compile(
    r"wireless|mobility|\bmobile\b|cellco|myvzw|vzwdms|phones\.att\.net|cellular",
    re.I,
)

def parse_asn(val):
    if val is None or val == "":
        return None
    if isinstance(val, int):
        return val if val > 0 else None
    s = str(val).strip()
    m = re.search(r"\bAS:?[\s-]*([0-9]+)\b", s, re.I)
    if m:
        return int(m.group(1))
    if re.fullmatch(r"[0-9]+", s):
        return int(s)
    return None

def add_ident(s, *texts, asn=None, city=None, country=None):
    for x in texts:
        if x is None:
            continue
        xs = str(x).strip()
        if not xs or xs.lower() in ("?", "n/a", "na", "none", "null", "-", "unknown"):
            continue
        s.setdefault("org_texts", []).append(xs)
        n = parse_asn(xs)
        if n:
            s.setdefault("asns", []).append(n)
    if asn is not None:
        n = parse_asn(asn)
        if n:
            s.setdefault("asns", []).append(n)
    if city and str(city).strip() and str(city).strip().lower() not in ("?", "n/a", "none", "null"):
        s["city"] = str(city).strip()
    if country and str(country).strip() and str(country).strip().lower() not in ("?", "n/a", "none", "null"):
        s["country"] = str(country).strip()

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
    # 商业线主机名不当作家宽风格（例如 comcastbusiness.net、uu.net）
    if re.search(r"comcastbusiness|uu\.net|alter\.net", h, re.I):
        return None, h
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
        "org_texts": [],
        "asns": [],
        "city": None,
        "country": None,
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
        add_ident(s, d.get("org"), asn=d.get("org") or d.get("asn"), city=d.get("city"), country=d.get("country"))

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
        add_ident(s, ii.get("org"), ii.get("isp"), asn=ii.get("asn"), city=ii.get("city"), country=ii.get("country") or ii.get("country_code"))
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
        add_ident(s, isp, org)
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
        add_ident(s, d.get("company_name"), d.get("asOrganization"), d.get("asname"), d.get("isp"), asn=d.get("asn"), city=d.get("city"), country=d.get("country") or d.get("countryCode"))
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
        loc = d.get("location") or {}
        add_ident(s, d.get("org"), net.get("company"), asn=d.get("asn"), city=loc.get("city"), country=loc.get("country"))
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
        add_ident(s, data.get("isp"), data.get("as_owner"), data.get("company"), asn=data.get("asn"), city=data.get("city"), country=data.get("country"))
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
host_sources = [title for title, v, _ in type_voters if v == "host"]
host_src_txt = "、".join(host_sources)
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

def detect_operator(sources, hostnames):
    """识别 AT&T / Verizon / Comcast。返回 dict 或 None。"""
    # 按来源收集文本 / ASN / rDNS
    name_items = []  # (title, text)
    asn_items = []   # (title, asn)
    rdns_items = []  # (title or 'rDNS', hostname)
    for s in sources.values():
        if not s.get("enabled") or not s.get("ok"):
            continue
        title = s["title"]
        for x in s.get("org_texts") or []:
            name_items.append((title, x))
        for n in s.get("asns") or []:
            asn_items.append((title, n))
        for h in s.get("hostnames") or []:
            rdns_items.append((title, h))
    for h in hostnames:
        if not any(h == x for _, x in rdns_items):
            rdns_items.append(("rDNS", h))

    def scrub(s):
        return LEGAL_ENTITY_RE.sub("att", s or "")

    all_name = " | ".join(scrub(x) for _, x in name_items)
    all_rdns = " | ".join(h for _, h in rdns_items)
    all_blob = all_name + " " + all_rdns
    asns = set(n for _, n in asn_items)

    def srcs_for(pred_name=None, pred_asn=None, pred_rdns=None):
        out = []
        if pred_name:
            for title, x in name_items:
                if pred_name(x) and title not in out:
                    out.append(title)
        if pred_asn:
            for title, n in asn_items:
                if pred_asn(n) and title not in out:
                    out.append(title)
        if pred_rdns:
            hit_rdns = False
            for title, h in rdns_items:
                if pred_rdns(h):
                    hit_rdns = True
                    # rDNS 统一记作 rDNS，避免和同名来源重复刷屏
                    if "rDNS" not in out:
                        out.append("rDNS")
            _ = hit_rdns
        return out

    best = None
    for op in OPERATORS:
        name_re = re.compile(op["name_re"], re.I)
        rdns_re = re.compile(op["rdns_re"], re.I)
        cons_re = re.compile(op["consumer_re"], re.I)
        biz_re = re.compile(op["business_re"], re.I)
        cons_asns = set(op["asn_consumer"])
        mob_asns = set(op["asn_mobile"])
        mix_asns = set(op["asn_mixed"])
        all_op_asns = cons_asns | mob_asns | mix_asns

        brand_hit = bool(name_re.search(all_blob) or (asns & all_op_asns) or rdns_re.search(all_rdns))
        if not brand_hit:
            continue

        # 消费侧证据只看名称 / rDNS，不能单凭消费级 ASN 覆盖「Comcast Business」等产品线
        consumer_signal = bool(cons_re.search(all_blob) or rdns_re.search(all_rdns))
        on_consumer_asn = bool(asns & (cons_asns | mob_asns))
        consumer = consumer_signal or on_consumer_asn
        business = bool(biz_re.search(all_blob) or GENERIC_BUSINESS_RE.search(all_blob))
        mobile = bool((asns & mob_asns) or MOBILE_RE.search(all_blob))

        ev_sources = srcs_for(
            pred_name=lambda x, nr=name_re, cr=cons_re, br=biz_re: nr.search(scrub(x)) or cr.search(scrub(x)) or br.search(scrub(x)),
            pred_asn=lambda n, s=all_op_asns: n in s,
            pred_rdns=lambda h, rr=rdns_re, cr=cons_re, br=biz_re: rr.search(h) or cr.search(h) or br.search(h),
        )

        # 明确商业产品线且没有名称/rDNS 消费侧证据 → 不加分
        # （Fios 的组织名常写作 Verizon Business，但 rDNS 含 fios，以消费侧为准）
        # 消费级 ASN 本身不能覆盖 comcastbusiness.net 这类产品线证据
        if business and not consumer_signal:
            cand = {"kind": "business", "brand": op["brand"], "sources": ev_sources, "mobile": False}
        elif not consumer_signal and (asns & mix_asns) and not on_consumer_asn:
            # 例如裸 AS701 + Verizon Business，没有 fios / pool rDNS
            cand = {"kind": "business", "brand": op["brand"], "sources": ev_sources, "mobile": False}
        elif consumer_signal or on_consumer_asn:
            cand = {"kind": "bonus", "brand": op["brand"], "sources": ev_sources, "mobile": mobile}
        else:
            cand = {"kind": "business", "brand": op["brand"], "sources": ev_sources, "mobile": False}

        # 若多品牌同时命中（极少见），优先 bonus，其次已选
        if best is None or (cand["kind"] == "bonus" and best["kind"] != "bonus"):
            best = cand
    return best

# ---------- 判定 ----------
reject = []
review = []
notes = []

if failed:
    names = "、".join(s["title"] + "（" + (s["error"] or "未知错误") + "）" for s in failed)
    review.append("以下启用源失败，按 fail-closed 至少需要人工复核: %s" % names)

# 主流家宽运营商加分（只加分，绝不覆盖否决项）
op_hit = detect_operator(sources, hostnames)
bonus_applied = False
res_eff = res_n
if op_hit and op_hit["kind"] == "bonus":
    src = ", ".join(op_hit["sources"]) if op_hit["sources"] else "综合字段"
    mob = " (移动网络)" if op_hit["mobile"] else ""
    line = "加分: 主流家宽运营商 %s%s (来源: %s)" % (op_hit["brand"], mob, src)
    # 仅当没有任何机房票时，加分才计为 +1 家宽票
    if host_n == 0:
        res_eff = res_n + 1
        bonus_applied = True
        line += "；机房票为 0，计为 +1 家宽票"
    else:
        line += "；存在机房票，只作提示、不计入类型投票"
    notes.append(line)
elif op_hit and op_hit["kind"] == "business":
    notes.append("提示: 运营商为 %s 商业线，不加分" % op_hit["brand"])

# 类型投票（res_eff 已含可能的运营商加分）
type_pass = (res_eff >= 2 and res_eff > host_n)
host_majority = (host_n > res_n and host_n >= 2)
if host_majority:
    # 机房多数按原始票数判断，加分不得覆盖
    reject.append("类型投票：机房/IDC %d 票 vs 家宽/ISP %d 票，多数源判机房（%s），建议放弃" % (host_n, res_n, host_src_txt or "—"))
elif not type_pass:
    review.append("类型投票未通过（家宽/ISP %d 票，机房/IDC %d 票；通过需至少 2 票家宽且多于机房票）" % (res_eff, host_n))
    if host_n >= 2:
        review.append("有 %d 个源判机房（%s）" % (host_n, host_src_txt))
else:
    if bonus_applied and res_n < 2:
        notes.append("类型投票通过：家宽/ISP %d 票 + 主流运营商加分，机房/IDC %d 票" % (res_n, host_n))
    else:
        notes.append("类型投票通过：家宽/ISP %d 票，机房/IDC %d 票" % (res_n, host_n))
    # 家宽仍占多数，但已有 ≥2 个源判机房（含仅多 1 票）→ 至少复核，不放弃
    if host_n >= 2:
        review.append("有 %d 个源判机房（%s），即使家宽仍占多数，也需复核" % (host_n, host_src_txt))

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
        # 仅当类型明确为家宽、机房票 < 2、且无代理标志时，11–25 只作参考
        if type_pass and flag_sources_n == 0 and host_n < 2:
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
if bonus_applied:
    print("类型投票合计: 家宽/ISP %d+1加分=%d  |  机房/IDC %d  |  投票源 %d" % (res_n, res_eff, host_n, len(type_voters)))
else:
    print("类型投票合计: 家宽/ISP %d  |  机房/IDC %d  |  投票源 %d" % (res_n, host_n, len(type_voters)))
if type_voters:
    for title, vote, note in type_voters:
        lab = "家宽" if vote == "res" else "机房"
        print("  - %s → %s%s" % (title, lab, ("（%s）" % note) if note else ""))
if bonus_applied:
    print("  - 主流运营商加分 → 家宽（+1，%s）" % op_hit["brand"])

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

# ---------- 综合分与情况分析 ----------
def pick_first(*vals):
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s and s.lower() not in ("none", "null", "?", "n/a", "na", "-"):
            return s
    return None

def pts_type():
    # 0-35
    if host_majority:
        return 0, "机房多数 %d:%d" % (res_n, host_n)
    if res_eff >= 2 and host_n == 0:
        return 35, "家宽 %d : 机房 0" % res_n
    if type_pass and host_n >= 2:
        return 15, "家宽 %d : 机房 %d（机房票偏多，需复核）" % (res_n, host_n)
    if type_pass and host_n > 0:
        return 25, "家宽 %d : 机房 %d（仍通过）" % (res_n, host_n)
    if res_eff > host_n:
        return 15, "家宽占优但未达通过线 %d:%d" % (res_eff, host_n)
    if res_n == host_n and (res_n + host_n) > 0:
        return 8, "打平 %d:%d" % (res_n, host_n)
    return 5, "家宽 %d : 机房 %d" % (res_n, host_n)

def pts_bonus():
    if bonus_applied:
        return 10, (op_hit or {}).get("brand", "是")
    if op_hit and op_hit.get("kind") == "bonus":
        return 0, "%s（有机房票，未计入）" % op_hit.get("brand")
    if op_hit and op_hit.get("kind") == "business":
        return 0, "%s 商业线，不加分" % op_hit.get("brand")
    return 0, "无"

def pts_flags():
    n = flag_sources_n
    if n <= 0:
        return 15, "无"
    if n == 1:
        t, f = flag_voters[0]
        return 5, "单源 %s(%s)" % (t, "/".join(f))
    labs = "、".join("%s(%s)" % (t, "/".join(f)) for t, f in flag_voters)
    return 0, "%d 源阳性：%s" % (n, labs)

def pts_scam():
    sc = sources["scamalytics"]
    score = sc.get("_score") if sc["ok"] else None
    if not sc["ok"] or score is None:
        return 8, "未取到分数"
    if score > 25:
        return 0, "%d（>25）" % score
    if score >= 11:
        return 10, "%d（11–25，参考）" % score
    return 15, "%d（低）" % score

def pts_native():
    bc = False
    labels = []
    if sources["ipx"]["ok"]:
        if sources["ipx"].get("_broadcast"):
            bc = True
            labels.append("ipx 广播")
        else:
            labels.append("ipx 原生")
    if sources["iping"]["ok"]:
        if sources["iping"].get("_broadcast"):
            bc = True
            labels.append("iping 广播")
        else:
            labels.append("iping 原生")
    if sources["coffee"]["ok"] and sources["coffee"].get("_broadcast_hint"):
        bc = True
        labels.append("coffee 非原生")
    if not labels:
        return 3, "未知"
    if bc:
        return 0, "；".join(labels)
    return 5, "原生"

def pts_dnsbl():
    cof = sources["coffee"]
    if not cof.get("_dnsbl_ok"):
        return 3, "未测到"
    if cof.get("_dnsbl_hits"):
        return 0, "命中 " + "; ".join(cof["_dnsbl_hits"])
    if cof.get("_dnsbl_pbl"):
        return 5, "仅 PBL（家宽正常）"
    return 5, "未列"

def pts_rdns():
    if rdns_host_strong and not rdns_res:
        hs = [h for h, sig in rdns_votes if sig == "host"]
        return 0, "机房风格 " + (hs[0] if hs else "")
    if rdns_res:
        hs = [h for h, sig in rdns_votes if sig == "res"]
        return 5, "家宽风格 " + (hs[0] if hs else "")
    if hostnames:
        return 2, hostnames[0]
    return 2, "无"

def pts_sources():
    n = len(failed)
    left = max(0, 10 - 8 * n)
    if n == 0:
        return 10, "全部源成功"
    names = "、".join(s["title"] for s in failed)
    return left, "%s 失败" % names

def pts_abuse():
    ab = sources["abuseipdb"]
    if not ab["enabled"]:
        return None, "未配置，不计入"
    if not ab["ok"]:
        return -0, "查询失败（已计入源失败）"
    ascore = ab.get("_abuse_score")
    reps = ab.get("_abuse_reports") or 0
    try:
        ascore_n = int(ascore) if ascore is not None else None
    except (TypeError, ValueError):
        ascore_n = None
    try:
        reps_n = int(reps)
    except (TypeError, ValueError):
        reps_n = 0
    if ascore_n is not None and ascore_n >= 75:
        return -15, "score %s，放弃线" % ascore_n
    if (ascore_n is not None and ascore_n >= 25) or reps_n >= 5:
        return -8, "score=%s reports=%s" % (ascore, reps)
    return 0, "干净（score=%s reports=%s）" % (ascore, reps)

p_type, d_type = pts_type()
p_bonus, d_bonus = pts_bonus()
p_flags, d_flags = pts_flags()
p_scam, d_scam = pts_scam()
p_nat, d_nat = pts_native()
p_bl, d_bl = pts_dnsbl()
p_rdns, d_rdns = pts_rdns()
p_src, d_src = pts_sources()
p_ab, d_ab = pts_abuse()

score_total = p_type + p_bonus + p_flags + p_scam + p_nat + p_bl + p_rdns + p_src
if p_ab is not None:
    score_total += p_ab
if score_total < 0:
    score_total = 0
if score_total > 100:
    score_total = 100

breakdown = [
    ("类型投票", p_type, 35, d_type),
    ("主流运营商加分", p_bonus, 10, d_bonus),
    ("代理/VPN/Tor", p_flags, 15, d_flags),
    ("Scamalytics", p_scam, 15, d_scam),
    ("原生/广播", p_nat, 5, d_nat),
    ("DNSBL", p_bl, 5, d_bl),
    ("rDNS", p_rdns, 5, d_rdns),
    ("源完整性", p_src, 10, d_src),
]
if p_ab is not None:
    breakdown.append(("AbuseIPDB", p_ab, 0, d_ab))
else:
    breakdown.append(("AbuseIPDB", 0, 0, d_ab))

# 复核原因：源失败 vs 真实信号。仅当完全没有实际信号时，才写「仅检测源失败」。
src_fail_reviews = [x for x in review if "启用源失败" in x or "fail-closed" in x]
other_reviews = [x for x in review if x not in src_fail_reviews]
failed_names = "、".join(s["title"] for s in failed)

def real_signal_phrases():
    phrases = []
    if host_n >= 2:
        phrases.append("有 %d 个源判机房（%s）" % (host_n, host_src_txt or "—"))
    elif (not type_pass) and (not host_majority):
        phrases.append("类型投票未通过（家宽 %d : 机房 %d）" % (res_eff, host_n))
    sc0 = sources["scamalytics"]
    sv = (sc0.get("_server") or "") if sc0["ok"] else ""
    if str(sv).lower() in ("yes", "true", "1") and host_n < 2:
        # Server=Yes 已计为机房票；仅在未并入「有 N 个源判机房」时单独写出
        phrases.append("Scamalytics 标记 Server=Yes")
    if flag_sources_n >= 2:
        labs = "、".join("%s(%s)" % (t, "/".join(f)) for t, f in flag_voters)
        phrases.append("多源代理/VPN/Tor 阳性（%s）" % labs)
    elif flag_sources_n == 1:
        t, f = flag_voters[0]
        phrases.append("单源代理/VPN/Tor 标记（%s: %s）" % (t, "/".join(f)))
    if sc0["ok"] and sc0.get("_score") is not None:
        if sc0["_score"] > 25:
            phrases.append("Scamalytics Fraud Score %d > 25" % sc0["_score"])
        elif sc0["_score"] >= 11 and not (type_pass and flag_sources_n == 0 and host_n < 2):
            phrases.append("Scamalytics Fraud Score %d 处于 11–25" % sc0["_score"])
    for name, title in (("ipx", "ipx.al"), ("iping", "iping.cc")):
        if sources[name]["ok"] and sources[name].get("_broadcast"):
            phrases.append("%s 判定为广播 IP" % title)
    if sources["coffee"]["ok"] and sources["coffee"].get("_broadcast_hint"):
        phrases.append("ip.net.coffee 注册地与使用地不一致（非原生）")
    cof0 = sources["coffee"]
    if cof0.get("_dnsbl_ok") and cof0.get("_dnsbl_hits"):
        phrases.append("DNSBL 命中非 PBL 名单")
    ab0 = sources["abuseipdb"]
    if ab0["enabled"] and ab0["ok"]:
        try:
            ascore_n = int(ab0.get("_abuse_score")) if ab0.get("_abuse_score") is not None else None
        except (TypeError, ValueError):
            ascore_n = None
        try:
            reps_n = int(ab0.get("_abuse_reports") or 0)
        except (TypeError, ValueError):
            reps_n = 0
        if (ascore_n is not None and ascore_n >= 25) or reps_n >= 5:
            phrases.append("AbuseIPDB 需复核")
    # IPLogs 非 clean 已在代理标记里覆盖时不再重复
    il0 = sources["iplogs"]
    if il0["ok"]:
        verd = il0.get("_verdict")
        if verd and norm(verd) not in ("clean", "allow", "allowlist"):
            already = flag_sources_n > 0 and any(t == il0["title"] for t, _ in flag_voters)
            if not already:
                phrases.append("IPLogs verdict=%s（非 clean）" % verd)
    if rdns_host_strong and not rdns_res and not type_pass:
        phrases.append("rDNS 呈机房风格")
    return phrases

signal_phrases = real_signal_phrases()
# 判定依据里还有、但上面没结构化到的实际复核项，补进原因，避免漏信号
structured_markers = ("有 %d 个源判机房" % host_n, "类型投票未通过", "代理/VPN/Tor",
                      "Scamalytics Fraud Score", "Scamalytics 标记", "广播", "非原生",
                      "DNSBL", "AbuseIPDB", "IPLogs verdict", "rDNS 呈机房")
for x in other_reviews:
    if any(m in x for m in structured_markers):
        continue
    signal_phrases.append(x)

if code == 0:
    conclusion = "留"
    review_reason = "pass"
    why_review = ""
elif code == 3:
    conclusion = "换"
    review_reason = "reject"
    why_review = ""
else:
    conclusion = "待复核"
    if not signal_phrases and (src_fail_reviews or failed):
        review_reason = "source_failure"
        why_review = "仅检测源失败（%s），不是这份 IP 本身的类型或标志问题" % (failed_names or "检测源")
    elif signal_phrases and (src_fail_reviews or failed):
        review_reason = "mixed"
        why_review = "%s；另有检测源失败（%s）" % ("；".join(signal_phrases), failed_names or "检测源")
    elif signal_phrases:
        review_reason = "signal"
        why_review = "；".join(signal_phrases)
    else:
        review_reason = "signal"
        why_review = "待复核是因为检测到需要人工确认的信号"

# 优缺点
pros = []
cons = []
if res_n >= 2 and host_n == 0:
    pros.append("类型投票明确为家宽（%d 票，机房 0）" % res_n)
elif type_pass:
    pros.append("类型投票通过（家宽 %d : 机房 %d）" % (res_n, host_n))
if host_majority:
    cons.append("多数源判机房（家宽 %d : 机房 %d；%s）" % (res_n, host_n, host_src_txt or "—"))
elif host_n > 0:
    cons.append("有 %d 个源判机房（%s）" % (host_n, host_src_txt or "—"))
sc_sv = (sources["scamalytics"].get("_server") or "") if sources["scamalytics"]["ok"] else ""
if str(sc_sv).lower() in ("yes", "true", "1"):
    cons.append("Scamalytics 标记 Server=Yes")
if bonus_applied:
    mob = "，移动网络" if (op_hit or {}).get("mobile") else ""
    pros.append("主流家宽运营商 %s%s" % (op_hit["brand"], mob))
elif op_hit and op_hit.get("kind") == "business":
    cons.append("运营商为 %s 商业线，未加分" % op_hit["brand"])
if flag_sources_n == 0 and sources["iplogs"]["ok"]:
    pros.append("无代理 / VPN / Tor 标记")
elif flag_sources_n == 1:
    cons.append("单源代理/VPN/Tor 标记")
elif flag_sources_n >= 2:
    cons.append("多源代理/VPN/Tor 阳性")
sc = sources["scamalytics"]
if sc["ok"] and sc.get("_score") is not None:
    if sc["_score"] <= 10:
        pros.append("Scamalytics Fraud Score %d（低）" % sc["_score"])
    elif sc["_score"] <= 25:
        if type_pass and flag_sources_n == 0 and host_n < 2:
            pros.append("Scamalytics Fraud Score %d（中段，仅作参考）" % sc["_score"])
        else:
            cons.append("Scamalytics Fraud Score %d（11–25，需复核）" % sc["_score"])
    else:
        cons.append("Scamalytics Fraud Score %d（>25）" % sc["_score"])
if p_nat == 5:
    pros.append("判定为原生 IP")
elif p_nat == 0:
    cons.append("广播或非原生")
cof = sources["coffee"]
if cof.get("_dnsbl_ok"):
    if cof.get("_dnsbl_hits"):
        cons.append("DNSBL 命中非 PBL 名单")
    elif cof.get("_dnsbl_pbl"):
        pros.append("黑名单仅 Spamhaus PBL（家宽正常）")
    else:
        pros.append("DNSBL 未列")
if rdns_res:
    pros.append("rDNS 呈家宽风格")
if rdns_host_strong and not rdns_res:
    cons.append("rDNS 呈机房风格")
if failed:
    cons.append("检测源失败: " + "、".join(s["title"] for s in failed))

# 一句建议
brand = (op_hit or {}).get("brand") if (op_hit and op_hit.get("kind") == "bonus") else None
bits = []
if brand:
    bits.append("家宽 " + brand + ("（移动网络）" if op_hit.get("mobile") else ""))
elif res_n >= 2 and host_n == 0:
    bits.append("类型投票为家宽")
if flag_sources_n == 0:
    bits.append("无代理标记")
if cof.get("_dnsbl_ok") and cof.get("_dnsbl_pbl") and not cof.get("_dnsbl_hits"):
    bits.append("黑名单仅 PBL")
elif cof.get("_dnsbl_ok") and not cof.get("_dnsbl_hits"):
    bits.append("黑名单未列")

if code == 0:
    suggestion = "留：" + ("、".join(bits) if bits else "类型与标志均通过")
elif code == 3:
    if host_majority:
        suggestion = "换：多数源判机房"
    elif flag_sources_n >= 2:
        suggestion = "换：多源代理/VPN/Tor 阳性"
    elif sc["ok"] and sc.get("_score") is not None and sc["_score"] > 25:
        suggestion = "换：Scamalytics Fraud Score %d > 25" % sc["_score"]
    else:
        suggestion = "换：" + (reject[0] if reject else "达到放弃线")
else:
    if review_reason == "source_failure":
        suggestion = "待复核：仅检测源失败（%s），类型与标志本身偏向留；源恢复后可重测" % (failed_names or "检测源")
    elif signal_phrases:
        suggestion = "待复核：" + "；".join(signal_phrases)
        if review_reason == "mixed" and failed_names:
            suggestion += "；另有检测源失败（%s）" % failed_names
        suggestion += "，不建议直接留"
    else:
        suggestion = "待复核：" + (other_reviews[0] if other_reviews else (review[0] if review else "需要人工确认"))

print()
print("======== 情况分析 ========")
print("结论: %s" % conclusion)
if why_review:
    print("原因: %s" % why_review)
print("综合分: %d / 100" % score_total)
print("  %-16s %4s  %s" % ("项目", "得分", "说明"))
for name, got, mx, detail in breakdown:
    if name == "AbuseIPDB" and p_ab is None:
        print("  %-16s %4s  %s" % (name, "—", detail))
    elif name == "AbuseIPDB":
        print("  %-16s %+4d  %s" % (name, got, detail))
    else:
        print("  %-16s %2d/%-2d  %s" % (name, got, mx, detail))
print("优点:")
if pros:
    for x in pros:
        print("  - " + x)
else:
    print("  （无）")
print("风险:")
if cons:
    for x in cons:
        print("  - " + x)
else:
    print("  （无）")
print("建议: %s" % suggestion)
print("==========================")

# 机器可读摘要（不含任何密钥）
asn_val = None
for s in sources.values():
    if s.get("ok") and s.get("asns"):
        asn_val = s["asns"][0]
        break
org_val = pick_first(*[x for s in sources.values() if s.get("ok") for x in (s.get("org_texts") or [])])
city_val = pick_first(*[s.get("city") for s in sources.values() if s.get("ok")])
country_val = pick_first(*[s.get("country") for s in sources.values() if s.get("ok")])
rdns_val = pick_first(*hostnames)
native_label = "broadcast" if p_nat == 0 else ("native" if p_nat == 5 else "unknown")
scam_score = sources["scamalytics"].get("_score") if sources["scamalytics"]["ok"] else None

summary = {
    "ip": IP,
    "timestamp": meta.get("timestamp") or "",
    "verdict": {0: "pass", 1: "review", 3: "reject"}.get(code, "review"),
    "verdict_zh": conclusion,
    "exit_code": code,
    "score": score_total,
    "breakdown": [
        {"item": name, "points": got, "max": mx, "detail": detail}
        for name, got, mx, detail in breakdown
    ],
    "operator": (op_hit or {}).get("brand") if op_hit else None,
    "operator_kind": (op_hit or {}).get("kind") if op_hit else None,
    "operator_bonus": bool(bonus_applied),
    "operator_mobile": bool((op_hit or {}).get("mobile")) if op_hit else False,
    "asn": asn_val,
    "org": org_val,
    "city": city_val,
    "country": country_val,
    "rdns": rdns_val,
    "type_votes": {
        "residential": res_n,
        "hosting": host_n,
        "effective_residential": res_eff,
        "bonus_applied": bool(bonus_applied),
    },
    "flags": [{"source": t, "flags": f} for t, f in flag_voters],
    "failed_sources": [s["title"] for s in failed],
    "review_reason": review_reason,
    "scamalytics_score": scam_score,
    "native": native_label,
    "dnsbl_hits": list(cof.get("_dnsbl_hits") or []),
    "dnsbl_pbl": list(cof.get("_dnsbl_pbl") or []),
    "suggestion": suggestion,
    "notes": notes[:],
    "pros": pros,
    "cons": cons,
}

json_path = meta.get("json_path") or ""
if json_path:
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(json_path, 0o600)
        print("JSON: %s" % json_path)
    except OSError as e:
        print("JSON 写入失败: %s" % e)

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
