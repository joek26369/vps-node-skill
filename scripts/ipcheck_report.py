# -*- coding: utf-8 -*-
"""ip-check-lite 六段报告。"""
from __future__ import print_function

import json
import os
import re
import socket
import subprocess
import sys
import time
import tempfile
from datetime import datetime
from pathlib import Path

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

UNLOCK_SERVICES = [
    "TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "Reddit",
    "ChatGPT", "Claude", "Gemini",
]

NOTE_UNLOCK_ALIASES = {
    "tiktok": "TikTok", "tt": "TikTok",
    "disney": "Disney+", "disney+": "Disney+", "disneyplus": "Disney+",
    "netflix": "Netflix", "nf": "Netflix",
    "youtube": "YouTube", "yt": "YouTube", "ytb": "YouTube",
    "amazonpv": "AmazonPV", "amazon": "AmazonPV", "prime": "AmazonPV",
    "primevideo": "AmazonPV", "amazonprime": "AmazonPV",
    "reddit": "Reddit",
    "chatgpt": "ChatGPT", "gpt": "ChatGPT", "openai": "ChatGPT",
    "claude": "Claude", "anthropic": "Claude",
    "gemini": "Gemini", "bard": "Gemini",
}

# 状态词：左边是用户可能写的，右边是报告用的状态；原生/DNS 另作方式
NOTE_STATUS_MAP = {
    "ok": "解锁", "yes": "解锁", "unlock": "解锁", "unlocked": "解锁",
    "pass": "解锁", "open": "解锁", "on": "解锁",
    "解锁": "解锁", "原生": "解锁", "native": "解锁",
    "dns": "解锁",
    "blocked": "屏蔽", "block": "屏蔽", "no": "屏蔽", "deny": "屏蔽",
    "denied": "屏蔽", "off": "屏蔽", "ban": "屏蔽",
    "屏蔽": "屏蔽", "不可用": "屏蔽",
    "self": "仅自制", "自制": "仅自制", "仅自制": "仅自制", "originals": "仅自制",
    "app": "仅APP", "仅app": "仅APP", "仅APP": "仅APP",
    "web": "仅网页", "仅网页": "仅网页",
    "fail": "失败", "failed": "失败", "失败": "失败",
    "untested": "未测", "未测": "未测",
}

HIGH_FLAG_SOURCES = ("scamalytics", "ipqs", "ipquality", "ipdata", "ipregistry", "ipinfo")



DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN", "mixed"),
    ("sbl.spamhaus.org", "Spamhaus SBL", "black"),
    ("xbl.spamhaus.org", "Spamhaus XBL", "black"),
    ("pbl.spamhaus.org", "Spamhaus PBL", "policy"),
    ("css.spamhaus.org", "Spamhaus CSS", "black"),
    ("bl.spamcop.net", "SpamCop", "black"),
    ("b.barracudacentral.org", "Barracuda", "black"),
    ("dnsbl.sorbs.net", "SORBS", "mixed"),
    ("dul.dnsbl.sorbs.net", "SORBS DUL", "policy"),
    ("socks.dnsbl.sorbs.net", "SORBS SOCKS", "black"),
    ("http.dnsbl.sorbs.net", "SORBS HTTP", "black"),
    ("misc.dnsbl.sorbs.net", "SORBS misc", "black"),
    ("zombie.dnsbl.sorbs.net", "SORBS zombie", "black"),
    ("cbl.abuseat.org", "CBL", "black"),
    ("psbl.surriel.com", "PSBL", "black"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT L1", "black"),
    ("dnsbl-2.uceprotect.net", "UCEPROTECT L2", "black"),
    ("bl.mailspike.net", "Mailspike", "black"),
    ("ix.dnsbl.manitu.net", "Manitu", "black"),
    ("all.s5h.net", "S5H", "black"),
    ("dnsbl.dronebl.org", "DroneBL", "black"),
    ("bl.blocklist.de", "blocklist.de", "black"),
    ("truncate.gbudb.net", "GBUdb", "black"),
    ("hostkarma.junkemailfilter.com", "Hostkarma", "mixed"),
    ("dnsbl.zapbl.net", "ZapBL", "black"),
    ("rbl.interserver.net", "InterServer", "black"),
    ("dnsbl.inps.de", "INPS", "black"),
    ("spam.spamrats.com", "SpamRATS spam", "black"),
    ("dyna.spamrats.com", "SpamRATS dyna", "policy"),
    ("noptr.spamrats.com", "SpamRATS noptr", "policy"),
    ("bl.spameatingmonkey.net", "SEM", "black"),
    ("backscatter.spameatingmonkey.net", "SEM backscatter", "policy"),
    ("ubl.unsubscore.com", "LashBack UBL", "black"),
    ("ips.backscatterer.org", "Backscatterer", "policy"),
    ("db.wpbl.info", "WPBL", "black"),
    ("opm.tornevall.org", "Tornevall", "black"),
    ("ix.manitu.net", "ix.manitu", "black"),
    ("rbl.megarbl.net", "MegaRBL", "black"),
    ("torexit.dan.me.uk", "dan.me.uk Tor", "black"),
    ("fnrbl.fast.net", "FastNet", "black"),
]

PBL_CODES = set(["127.0.0.10", "127.0.0.11"])
OPEN_RESOLVER = re.compile(r"^127\.255\.255\.")
FAKE_IP = re.compile(r"^198\.1[89]\.")


def want_color():
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


class C:
    def __init__(self, on):
        self.on = on
        self.reset = "\033[0m" if on else ""
        self.bold = "\033[1m" if on else ""
        self.red = "\033[31m" if on else ""
        self.green = "\033[32m" if on else ""
        self.yellow = "\033[33m" if on else ""
        self.cyan = "\033[36m" if on else ""
        self.bg_green = "\033[42m\033[37m\033[1m" if on else ""
        self.bg_yellow = "\033[43m\033[37m\033[1m" if on else ""
        self.bg_red = "\033[41m\033[37m\033[1m" if on else ""


def _dash(v):
    if v is None:
        return "—"
    s = str(v).strip()
    if s == "" or s.lower() in ("none", "null", "n/a", "na", "?", "-"):
        return "—"
    return s


def _bool_zh(v):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "是" if v else "否"
    s = str(v).strip().lower()
    if s in ("true", "yes", "1", "是"):
        return "是"
    if s in ("false", "no", "0", "否"):
        return "否"
    return "—"


def classify_type(label):
    if label is None:
        return None
    s = str(label).strip()
    if not s or s.lower() in ("none", "null", "n/a", "na", "?", "-"):
        return None
    n = s.lower()
    first = n.split("/")[0].strip()
    mapping = {
        "isp": "家宽", "fixed line isp": "家宽", "line isp": "家宽",
        "residential": "家宽", "resi": "家宽", "cable": "家宽", "fttx": "家宽", "dsl": "家宽",
        "mobile": "手机", "mobile isp": "手机", "wireless": "手机", "cell": "手机", "mob": "手机",
        "hosting": "机房", "datacenter": "机房", "data center": "机房", "data centre": "机房",
        "dch": "机房", "idc": "机房", "server": "机房", "cloud": "机房", "host": "机房",
        "机房": "机房", "家宽": "家宽", "商业": "商业", "手机": "手机",
        "cdn": "CDN", "content delivery network": "CDN",
        "business": "商业", "commercial": "商业", "com": "商业", "company": "商业",
        "education": "教育", "edu": "教育", "university/college/school": "教育",
        "government": "政府", "gov": "政府",
        "organization": "组织", "org": "组织",
        "banking": "银行", "military": "军队", "mil": "军队",
        "library": "图书馆", "lib": "图书馆",
        "reserved": "保留", "rsv": "保留", "ses": "蜘蛛",
    }
    if n in mapping:
        return mapping[n]
    if first in mapping:
        return mapping[first]
    if "datacenter" in n or "data center" in n:
        return "机房"
    return s


def _manual_tag(text):
    s = "" if text is None else str(text)
    if "（手动）" in s:
        return s.replace("（手动）", ""), "（手动）"
    return s, ""


def color_type(text, c):
    base, tag = _manual_tag(text)
    if base in ("家宽", "手机"):
        return c.bg_green + " " + base + " " + c.reset + tag
    if base in ("机房", "CDN", "蜘蛛"):
        return c.bg_red + " " + base + " " + c.reset + tag
    if base not in ("—", "未配置", None, "") and "不可用" not in base:
        return c.bg_yellow + " " + base + " " + c.reset + tag
    return (text or "—")


def color_bool(text, c):
    base, tag = _manual_tag(text)
    if base == "是":
        return c.red + c.bold + "是" + c.reset + tag
    if base == "否":
        return c.green + c.bold + "否" + c.reset + tag
    return text


def color_level(level, c):
    if not level or level in ("—", "未配置"):
        return level
    if "不可用" in str(level):
        return level
    if any(k in level for k in ("极高", "高风险", "建议封禁", "存在风险")):
        return c.red + c.bold + level + c.reset
    if any(k in level for k in ("中", "较高", "可疑")):
        return c.yellow + c.bold + level + c.reset
    if "低" in level:
        return c.green + c.bold + level + c.reset
    return level


def scam_level(score):
    try:
        n = float(score)
    except (TypeError, ValueError):
        return None
    if n < 20:
        return "低风险"
    if n < 60:
        return "中风险"
    if n < 90:
        return "高风险"
    return "极高风险"


def abuse_level(score):
    try:
        n = float(score)
    except (TypeError, ValueError):
        return None
    if n < 25:
        return "低风险"
    if n < 75:
        return "高风险"
    return "建议封禁"


def ip2_level(score):
    try:
        n = float(score)
    except (TypeError, ValueError):
        return None
    if n < 33:
        return "低风险"
    if n < 66:
        return "中风险"
    return "高风险"


def ipqs_level(score):
    try:
        n = float(score)
    except (TypeError, ValueError):
        return None
    if n < 75:
        return "低风险"
    if n < 85:
        return "可疑IP"
    if n < 90:
        return "存在风险"
    return "高风险"


def dbip_level(text):
    if not text:
        return None
    s = str(text).strip().lower()
    mapping = {
        "low": "低风险", "medium": "中风险", "high": "高风险",
        "低": "低风险", "中": "中风险", "高": "高风险",
        "低风险": "低风险", "中风险": "中风险", "高风险": "高风险",
    }
    if s in mapping:
        return mapping[s]
    # 截掉「风险」再试（「低风险」已在 mapping；「低」也在）
    s2 = s.replace("风险", "").strip()
    return mapping.get(s2)


def read_json_body(workdir, name):
    path = os.path.join(workdir, name + ".body")
    if not os.path.isfile(path):
        return None
    try:
        raw = open(path, "r", encoding="utf-8", errors="replace").read()
        if not raw.strip():
            return None
        return json.loads(raw)
    except (OSError, ValueError, TypeError):
        return None


def http_of(workdir, name):
    path = os.path.join(workdir, name + ".code")
    try:
        return open(path, "r", encoding="utf-8").read().strip()
    except OSError:
        return "000"


def load_extras(workdir):
    extras = {}
    for name in (
        "ipwho", "ipapi_is", "dbip", "ip2location", "ip_api",
        "ipregistry", "ipqs", "ipdata", "ipinfo_full",
    ):
        extras[name] = {"http": http_of(workdir, name), "data": read_json_body(workdir, name)}
    return extras

def _rev(ip):
    return ".".join(reversed(ip.split(".")))


def _doh_query(name, typ, timeout=6):
    """Query dns.google DoH. typ is A or PTR. Avoids Clash fake-ip on the box resolver."""
    try:
        from urllib.parse import quote
        qn = quote(name, safe=".-")
    except Exception:
        qn = name
    url = "https://dns.google/resolve?name=%s&type=%s" % (qn, typ)
    want = 1 if typ.upper() == "A" else (12 if typ.upper() == "PTR" else None)
    try:
        p = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout),
             "-H", "Accept: application/dns-json", url],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2,
        )
        if p.returncode != 0 or not p.stdout:
            return None, "doh_fail"
        data = json.loads(p.stdout.decode("utf-8", "replace"))
        answers = []
        for a in data.get("Answer") or []:
            if want is not None and a.get("type") != want:
                continue
            val = str(a.get("data") or "").strip().rstrip(".")
            if val:
                answers.append(val)
        if answers:
            return answers, "ok"
        if data.get("Status") == 3:
            return [], "nxdomain"
        return [], "empty"
    except Exception:
        return None, "error"


def _doh_a(name, timeout=6):
    return _doh_query(name, "A", timeout=timeout)


def _doh_ptr(name, timeout=6):
    return _doh_query(name, "PTR", timeout=timeout)


# ----- 硬证据：登记库 (RDAP/whois) 与 rDNS (DoH PTR + FCrDNS) -----
# 这不是第三方类型库，而是注册局与 DNS 本身的记录。

RES_PTR_RE = re.compile(
    r"(hsd\d*\.|fios|sbcglobal|lightspeed|\.att\.net|phones\.att\.net|"
    r"res\.spectrum\.com|\.rr\.com|res\.rr|charter\.|spectrum\.com|"
    r"\.cox\.net|\.cox\.com|wavecable|wavebroadband|"
    r"comcast\.net|xfinity|"
    r"(?:pool-|static-|dsl-).+\.verizon\.net|(?:east|west)\.verizon\.net|myvzw|"
    r"\bdyn\b|dhcp|\bdsl\b|adsl|cable|fiber|fibre|\bres\b|resid|"
    r"\bpool\b|\bcpe\b|pppoe|frontier|centurylink|qwest|"
    r"shawcable|rogers|videotron|telus|\bbt\.net|virginmedia|skybroadband|"
    r"t-online|wanadoo|optimum|suddenlink|\brcn\.|mediacom|wideopenwest)",
    re.I,
)
BIZ_PTR_RE = re.compile(r"comcastbusiness|uu\.net|alter\.net", re.I)
HOST_PTR_RE = re.compile(
    r"(vps|hosting|dedicated|colocation|\bcolo\b|datacenter|data-center|"
    r"digitalocean|linode|hetzner|vultr|contabo|\bovh\b|amazonaws|"
    r"googleusercontent|cloudapp|azure|akamai|leaseweb|hivelocity|"
    r"ip-\d+-\d+-\d+-\d+)",
    re.I,
)
HOST_PTR_WEAK_RE = re.compile(r"(\bstatic\b|\bcloud\b|\bserver\b)", re.I)

HOST_ORG_RE = re.compile(
    r"hosting|data\s*cent(?:er|re)|datacenter|data-center|\bcloud\b|\bvps\b|"
    r"\bproxy\b|netlab|\bcolo(?:cation)?\b|ipxo|ip-?rent|\bip rent\b|"
    r"\bleasing\b|\bleased?\b|leaseweb|serverfarm|dedicated\s*server|"
    r"ip\s*transit\s*reseller|prefix\s*lease",
    re.I,
)
LEASE_RE = re.compile(
    r"\bipxo\b|\bleased?\b|\bleasing\b|address[^\n]{0,40}rent|rented\s+to|"
    r"sub-allocat(?:ed|ion)[^\n]{0,40}leas",
    re.I,
)
ISP_ORG_RE = re.compile(
    r"\bcomcast\b|xfinity|\bcharter\b|\bspectrum\b|\bverizon\b|\bfios\b|"
    r"\bat&?t\b|sbcglobal|\bcox\b|wavecable|wave\s*g?\.?\s*broadband|wavecom|"
    r"bam\s*broadband|\bfrontier\b|centurylink|\bqwest\b|windstream|"
    r"\boptimum\b|suddenlink|\brcn\b|mediacom|wideopenwest|\bwow\b|"
    r"\brogers\b|\bshaw\b|\btelus\b|\bbell\b|virgin\s*media|\bsky\b|"
    r"t-mobile|deutsche\s*telekom|\bvodafone\b|\borange\b|\bbt\b|"
    r"telefonica|telstra|softbank|ntt\s*docomo|kddi",
    re.I,
)
CARRIER_ORG_RE = re.compile(
    r"\bgtt\b|\bcogent\b|level\s*3|\blumen\b|hurricane|he\.net|"
    r"\bntt\b|\btata\b|\bzayo\b|above\.net|\buunet\b|\btelia\b|pccw|"
    r"megapath",
    re.I,
)
COUNTRY_MAP = {
    "united states": "US", "usa": "US", "u.s.a.": "US", "u.s.": "US",
    "united kingdom": "GB", "great britain": "GB", "canada": "CA",
    "germany": "DE", "france": "FR", "netherlands": "NL", "japan": "JP",
    "australia": "AU", "china": "CN", "hong kong": "HK", "singapore": "SG",
    "ireland": "IE", "switzerland": "CH", "sweden": "SE", "brazil": "BR",
    "india": "IN", "korea": "KR", "south korea": "KR", "bulgaria": "BG",
}

ALLOC_ZH = {
    "direct allocation": "直接分配",
    "direct assignment": "直接指派",
    "allocation": "分配",
    "assignment": "指派",
    "reallocated": "再分配",
    "reassignment": "转分配",
    "reassigned": "转分配",
    "allocated pa": "PA 分配",
    "allocated pi": "PI 分配",
    "assigned pa": "PA 指派",
    "assigned pi": "PI 指派",
    "sub-allocated pa": "PA 再分配",
    "legacy": "历史分配",
}


def classify_ptr(hostname):
    """Return (style, style_zh) where style is res|host|host_weak|other|none."""
    if not hostname or hostname in ("?", "(无)", "null", "None"):
        return "none", "无 PTR"
    h = hostname.strip().rstrip(".")
    if not h:
        return "none", "无 PTR"
    if BIZ_PTR_RE.search(h):
        return "other", "商业线风格"
    res = bool(RES_PTR_RE.search(h))
    host_strong = bool(HOST_PTR_RE.search(h))
    host_weak = bool(HOST_PTR_WEAK_RE.search(h))
    if res and not host_strong:
        return "res", "家宽风格"
    if host_strong and not res:
        return "host", "服务器风格"
    if res and host_strong:
        return "other", "混合风格"
    if host_weak and not res:
        return "host_weak", "弱服务器风格"
    return "other", "其他"


def lookup_rdns(ip, timeout=6):
    """PTR via DoH + forward-confirm. Never uses the box stub resolver."""
    out = {
        "ptr": None, "ptrs": [], "fcrdns": False,
        "style": "none", "style_zh": "无 PTR", "error": None, "a_records": [],
    }
    if not ip or not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        out["error"] = "bad_ip"
        return out
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    ptrs, st = _doh_ptr(rev, timeout=timeout)
    if st in ("doh_fail", "error") or ptrs is None:
        out["error"] = st or "doh_fail"
        out["style_zh"] = "—"
        out["style"] = "unknown"
        return out
    if not ptrs:
        return out
    out["ptrs"] = ptrs
    out["ptr"] = ptrs[0]
    style, zh = classify_ptr(ptrs[0])
    out["style"], out["style_zh"] = style, zh
    addrs, ast = _doh_a(ptrs[0], timeout=timeout)
    out["a_records"] = addrs or []
    out["fcrdns"] = bool(addrs) and ip in addrs
    return out


def _vcard_fn(ent):
    v = ent.get("vcardArray")
    fn = org = adr_label = country = None
    if isinstance(v, list) and len(v) >= 2 and isinstance(v[1], list):
        for item in v[1]:
            if not item or not isinstance(item, (list, tuple)):
                continue
            key = item[0]
            val = item[3] if len(item) > 3 else None
            params = item[1] if len(item) > 1 and isinstance(item[1], dict) else {}
            if key == "fn" and val:
                fn = val if isinstance(val, str) else (val[0] if val else None)
            elif key == "org" and val:
                if isinstance(val, list):
                    org = " ".join(str(x) for x in val if x)
                else:
                    org = val
            elif key == "adr":
                if params.get("label"):
                    adr_label = params["label"]
                elif isinstance(val, list):
                    adr_label = "\n".join(str(x) for x in val if x)
            elif key in ("cc", "country"):
                country = val
    return fn, org, adr_label, country


def _country_from_text(text):
    if not text:
        return None
    lines = [x.strip() for x in re.split(r"[\n,;]+", str(text)) if x and x.strip()]
    if not lines:
        return None
    last = lines[-1]
    if re.fullmatch(r"[A-Za-z]{2}", last):
        return last.upper()
    return COUNTRY_MAP.get(last.lower()) or (last if len(last) <= 32 else None)


def _iter_entities(ents, depth=0):
    for ent in ents or []:
        yield depth, ent
        for item in _iter_entities(ent.get("entities") or [], depth + 1):
            yield item


def _cidr_from_range(start, end):
    import socket as _socket
    import struct
    import math
    try:
        a = struct.unpack("!I", _socket.inet_aton(start))[0]
        b = struct.unpack("!I", _socket.inet_aton(end))[0]
        if a > b:
            a, b = b, a
        span = b - a + 1
        if span <= 0 or (span & (span - 1)) != 0:
            return "%s - %s" % (start, end)
        length = 32 - int(math.log2(span))
        return "%s/%d" % (_socket.inet_ntoa(struct.pack("!I", a)), length)
    except Exception:
        if start and end:
            return "%s - %s" % (start, end)
        return start or end


def _date_only(s):
    if not s:
        return None
    raw = str(s).strip()
    try:
        t = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is not None:
            try:
                from zoneinfo import ZoneInfo
                dt = dt.astimezone(ZoneInfo("America/New_York"))
            except Exception:
                pass
        return dt.strftime("%Y-%m-%d")
    except Exception:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", raw)
        return m.group(1) if m else None


def parse_rdap(data):
    if not isinstance(data, dict) or not data:
        return None
    if not any(data.get(k) for k in ("handle", "startAddress", "cidr0_cidrs", "inetnum", "name", "objectClassName")):
        return None
    cidrs = []
    for c in data.get("cidr0_cidrs") or []:
        if isinstance(c, dict) and c.get("v4prefix") is not None and c.get("length") is not None:
            cidrs.append("%s/%s" % (c["v4prefix"], c["length"]))
        elif isinstance(c, str):
            cidrs.append(c)
    if not cidrs and data.get("cidr"):
        c = data.get("cidr")
        if isinstance(c, list):
            cidrs.extend(str(x) for x in c)
        else:
            cidrs.append(str(c))
    start, end = data.get("startAddress"), data.get("endAddress")
    if not cidrs and start:
        cidrs.append(_cidr_from_range(start, end or start))
    prefix_len = None
    for c in cidrs:
        m = re.search(r"/(\d+)$", c)
        if m:
            n = int(m.group(1))
            if prefix_len is None or n > prefix_len:
                prefix_len = n

    orgs = []
    countries = []
    if data.get("country"):
        countries.append(_country_from_text(data["country"]) or str(data["country"]).upper())
    for depth, ent in _iter_entities(data.get("entities") or []):
        fn, org, adr, cc = _vcard_fn(ent)
        roles = [str(x).lower() for x in (ent.get("roles") or [])]
        name = fn or org
        if name:
            orgs.append({"name": name, "roles": roles, "handle": ent.get("handle"), "depth": depth})
        if cc:
            countries.append(_country_from_text(cc) or str(cc))
        if adr:
            ctry = _country_from_text(adr)
            if ctry:
                countries.append(ctry)

    def _pick_org():
        for role in ("registrant", "administrative"):
            for o in orgs:
                if role in (o.get("roles") or []):
                    return o.get("name")
        return orgs[0]["name"] if orgs else None

    ev = {}
    for e in data.get("events") or []:
        act = (e.get("eventAction") or "").lower().replace(" ", "")
        dt = _date_only(e.get("eventDate"))
        if not dt:
            continue
        if act in ("registration", "registered", "lastchanged", "expiration"):
            ev[act] = dt
        elif "registr" in act:
            ev.setdefault("registration", dt)
        elif "chang" in act or "updat" in act:
            ev.setdefault("lastchanged", dt)

    remarks = []
    for r in data.get("remarks") or []:
        desc = r.get("description")
        if isinstance(desc, list):
            remarks.append(" ".join(str(x) for x in desc))
        elif desc:
            remarks.append(str(desc))
        elif r.get("title"):
            remarks.append(str(r["title"]))

    port43 = (data.get("port43") or "").lower()
    rir = None
    if "arin" in port43:
        rir = "ARIN"
    elif "ripe" in port43:
        rir = "RIPE"
    elif "apnic" in port43:
        rir = "APNIC"
    elif "lacnic" in port43:
        rir = "LACNIC"
    elif "afrinic" in port43:
        rir = "AFRINIC"
    if not rir:
        blob = " ".join(str(l.get("href") or "") for l in (data.get("links") or []))
        for name, key in (("ARIN", "arin"), ("RIPE", "ripe"), ("APNIC", "apnic"),
                          ("LACNIC", "lacnic"), ("AFRINIC", "afrinic")):
            if key in blob.lower():
                rir = name
                break

    typ = data.get("type") or data.get("status")
    if isinstance(typ, list):
        typ = ", ".join(str(x) for x in typ)
    typ_s = str(typ).strip() if typ else None
    typ_key = typ_s.lower() if typ_s else ""
    typ_zh = ALLOC_ZH.get(typ_key) or ALLOC_ZH.get(typ_key.replace("_", " "))

    country = None
    for c in countries:
        if c and re.fullmatch(r"[A-Z]{2}", c):
            country = c
            break
    if not country and countries:
        country = countries[0]

    return {
        "ok": True,
        "source": "rdap",
        "rir": rir,
        "org": _pick_org(),
        "orgs": orgs,
        "netname": data.get("name"),
        "handle": data.get("handle") or data.get("objectKey") or data.get("inetnum"),
        "cidr": ", ".join(cidrs) if cidrs else None,
        "prefix_len": prefix_len,
        "allocation": typ_s,
        "allocation_zh": typ_zh,
        "country": country,
        "registered": ev.get("registration"),
        "updated": ev.get("lastchanged"),
        "remarks": remarks,
        "start": start,
        "end": end,
    }


def parse_whois_text(text):
    if not text or not str(text).strip():
        return None
    fields = {}
    for line in str(text).splitlines():
        if ":" not in line or line.startswith("%") or line.startswith("#"):
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not k or not v:
            continue
        fields.setdefault(k, v)

    def first(*keys):
        for k in keys:
            if fields.get(k):
                return fields[k]
        return None

    org = first("org-name", "orgname", "organization", "organisation", "owner", "descr")
    netname = first("netname", "net name")
    handle = first("netrange", "net handle", "nethandle", "inetnum")
    cidr = first("cidr", "route")
    typ = first("nettype", "net type", "status")
    country = first("country")
    if country:
        country = _country_from_text(country) or country.upper()[:2]
    reg = _date_only(first("regdate", "reg date", "created"))
    upd = _date_only(first("updated", "last-modified", "changed"))
    typ_s = typ
    typ_zh = ALLOC_ZH.get((typ or "").lower()) if typ else None
    remarks = []
    for k, v in fields.items():
        if "comment" in k or "remark" in k:
            remarks.append(v)
    prefix_len = None
    if cidr and "/" in cidr:
        try:
            prefix_len = max(int(x.split("/")[-1]) for x in re.findall(r"\S+/\d+", cidr))
        except ValueError:
            pass
    return {
        "ok": True,
        "source": "whois",
        "rir": None,
        "org": org,
        "orgs": [{"name": org, "roles": ["registrant"]}] if org else [],
        "netname": netname,
        "handle": handle,
        "cidr": cidr,
        "prefix_len": prefix_len,
        "allocation": typ_s,
        "allocation_zh": typ_zh,
        "country": country,
        "registered": reg,
        "updated": upd,
        "remarks": remarks,
    }


def load_registry(workdir):
    data = read_json_body(workdir, "rdap")
    parsed = parse_rdap(data) if data else None
    srcf = Path(workdir) / "rdap.source"
    if parsed and srcf.is_file():
        try:
            parsed["rdap_endpoint"] = srcf.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            pass
    if parsed:
        return parsed
    whois_path = Path(workdir) / "whois.body"
    if whois_path.is_file():
        try:
            text = whois_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        parsed = parse_whois_text(text)
        if parsed:
            return parsed
    return {
        "ok": False, "source": None, "org": None, "netname": None, "handle": None,
        "cidr": None, "allocation": None, "allocation_zh": None, "country": None,
        "registered": None, "updated": None, "remarks": [], "prefix_len": None,
        "error": "rdap_unavailable",
    }


def _norm_org(s):
    s = str(s or "").lower()
    s = re.sub(
        r"\b(llc|l\.?l\.?c\.?|inc|incorporated|ltd|limited|corp|corporation|"
        r"co|communications?|services?|company|holdings?|group|opco|americas?|"
        r"enterprises?|international|the)\b",
        " ",
        s,
        flags=re.I,
    )
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return " ".join(s.split())


def orgs_match(a, b):
    na, nb = _norm_org(a), _norm_org(b)
    if not na or not nb:
        return False
    if na == nb or na in nb or nb in na:
        return True
    ta = {t for t in na.split() if len(t) >= 3}
    tb = {t for t in nb.split() if len(t) >= 3}
    return bool(ta and tb and (ta & tb))


KNOWN_ORG_RE = re.compile(
    r"\bgoogle\b|\bamazon\b|\bmicrosoft\b|\bmeta\b|\bfacebook\b|\bapple\b|"
    r"cloudflare|akamai|\boracle\b|\bibm\b|\bcisco\b|\btwitter\b|\bx corp\b|"
    r"\balibaba\b|\btencent\b|\bbaidu\b|\bhuawei\b|\bsamsung\b",
    re.I,
)


def _is_small_reseller(org):
    """Foo LLC style generic reseller; do not flag well-known carriers just for LLC."""
    if not org:
        return False
    if ISP_ORG_RE.search(org) or CARRIER_ORG_RE.search(org) or HOST_ORG_RE.search(org) or KNOWN_ORG_RE.search(org):
        return False
    words = re.findall(r"[A-Za-z0-9&]+", org)
    has_llc = bool(re.search(r"\b(llc|l\.l\.c\.|ltd|inc)\b", org, re.I))
    core = [w for w in words if w.lower() not in ("llc", "l", "c", "ltd", "inc", "the", "and", "of")]
    return has_llc and 0 < len(core) <= 2


def _recent_small(reg, prefix_len, months=36):
    if not reg or prefix_len is None or prefix_len < 21:
        return False
    try:
        d = datetime.strptime(reg, "%Y-%m-%d")
        now = datetime.now()
        return (now - d).days <= months * 31  # default window set at call site
    except Exception:
        return False


def assess_registry(reg, asn_org=None, operator=None, asn=None, operator_kind=None):
    """Compare registry org vs ASN/operator. Returns flags + summary bits."""
    flags = {
        "consistent_isp": False,
        "consistent": False,
        "mismatch": False,
        "reassigned": False,
        "hosting_org": False,
        "small_reseller": False,
        "leased": False,
        "recent_small": False,
        "isp_like": False,
        "carrier_like": False,
    }
    if not reg or not reg.get("ok"):
        return flags, []

    org = reg.get("org") or ""
    typ = (reg.get("allocation") or "").lower()
    remarks = " ".join(reg.get("remarks") or [])
    flags["isp_like"] = bool(org and ISP_ORG_RE.search(org))
    flags["carrier_like"] = bool(org and CARRIER_ORG_RE.search(org))
    flags["hosting_org"] = bool(org and HOST_ORG_RE.search(org))
    flags["small_reseller"] = _is_small_reseller(org)
    flags["leased"] = bool(LEASE_RE.search(remarks) or (org and LEASE_RE.search(org)))
    flags["recent_small"] = _recent_small(reg.get("registered"), reg.get("prefix_len"))
    flags["reassigned"] = bool(re.search(r"reassign|reallocat|sub-allocat", typ))

    # asn 可能是整数；只用组织名/运营商品牌做匹配，不用纯 ASN 号
    peers = []
    for x in (asn_org, operator):
        if x is None:
            continue
        xs = str(x).strip()
        if xs:
            peers.append(xs)
    matched = any(orgs_match(org, p) for p in peers) if org else False
    flags["consistent"] = bool(matched)
    flags["consistent_isp"] = bool(
        flags["consistent"] and flags["isp_like"] and not flags["carrier_like"]
        and not flags["hosting_org"]
    )
    # 商业线（Verizon Business 等）与 ASN 一致也不算偏家宽
    if (operator_kind == "business") or (org and re.search(r"\bbusiness\b", org, re.I)):
        flags["consistent_isp"] = False
    if org and peers and not matched:
        flags["mismatch"] = True

    bits = []
    if flags["consistent_isp"]:
        bits.append("登记单位 %s（ISP）与 ASN 一致" % org)
    elif flags["consistent"] and org:
        bits.append("登记单位 %s 与 ASN 一致" % org)
    elif flags["mismatch"] and org:
        other = asn_org or operator or ("AS%s" % asn if asn else None) or "—"
        if flags["reassigned"]:
            bits.append("登记单位 %s 相对 ASN 组织（%s）为转租/转分配" % (org, other))
        else:
            bits.append("登记单位 %s 与 ASN 组织（%s）不一致，可能转租/转分配" % (org, other))
    elif org:
        bits.append("登记单位 %s" % org)
    else:
        bits.append("登记单位 —")

    if flags["hosting_org"]:
        bits.append("登记单位像机房/代理/转售")
    if flags["small_reseller"] and not flags["hosting_org"]:
        bits.append("登记单位像小型转售 LLC")
    if flags["leased"]:
        bits.append("RDAP 备注含租用/IPXO 等租赁标记")
    if flags["recent_small"]:
        bits.append("近期登记的较小网段（/%s，%s）" % (reg.get("prefix_len"), reg.get("registered") or "—"))
    return flags, bits


def rdns_score(rdns):
    """Return (points, detail) for the existing rDNS score slot (max 5)."""
    if not rdns or rdns.get("style") == "unknown" or rdns.get("error"):
        return 2, "未测到"
    style = rdns.get("style") or "none"
    ptr = rdns.get("ptr") or ""
    fcr = bool(rdns.get("fcrdns"))
    if style == "host":
        return 0, "服务器风格 " + ptr
    if style == "res":
        if fcr:
            return 5, "家宽风格 + FCrDNS " + ptr
        return 3, "家宽风格（正反向不一致） " + ptr
    if style == "none":
        return 1, "无 PTR"
    if style == "host_weak":
        return 1, "弱服务器风格 " + (ptr or "")
    if ptr:
        extra = " + FCrDNS" if fcr else ""
        return 2, (rdns.get("style_zh") or "其他") + extra + " " + ptr
    return 1, "无 PTR"


def build_hard_evidence(rdns, registry, flags, bits):
    summary_parts = list(bits or [])
    if not rdns or rdns.get("style") in ("none", "unknown") or not rdns.get("ptr"):
        if rdns and rdns.get("error"):
            summary_parts.append("rDNS 未测到")
        else:
            summary_parts.append("无 PTR")
    else:
        piece = "rDNS %s %s" % (rdns.get("style_zh") or "", rdns.get("ptr") or "")
        if rdns.get("fcrdns"):
            piece += "（FCrDNS）"
        elif rdns.get("ptr"):
            piece += "（正反向不一致）"
        summary_parts.append(piece.strip())
    summary = "硬证据: " + "；".join(x for x in summary_parts if x)
    if flags.get("consistent_isp"):
        summary += " → 偏家宽(+)"
    return {
        "summary": summary,
        "registry": {
            "ok": bool(registry and registry.get("ok")),
            "source": (registry or {}).get("source"),
            "rir": (registry or {}).get("rir"),
            "org": (registry or {}).get("org"),
            "cidr": (registry or {}).get("cidr"),
            "netname": (registry or {}).get("netname"),
            "handle": (registry or {}).get("handle"),
            "allocation": (registry or {}).get("allocation"),
            "allocation_zh": (registry or {}).get("allocation_zh"),
            "country": (registry or {}).get("country"),
            "registered": (registry or {}).get("registered"),
            "updated": (registry or {}).get("updated"),
            "prefix_len": (registry or {}).get("prefix_len"),
            "remarks": (registry or {}).get("remarks") or [],
        },
        "flags": flags,
        "rdns": {
            "ptr": (rdns or {}).get("ptr"),
            "ptrs": (rdns or {}).get("ptrs") or [],
            "fcrdns": bool((rdns or {}).get("fcrdns")),
            "style": (rdns or {}).get("style"),
            "style_zh": (rdns or {}).get("style_zh"),
            "error": (rdns or {}).get("error"),
        },
    }

def classify_dnsbl_codes(codes, zone_kind):
    if not codes:
        return "clean"
    if any(FAKE_IP.match(c) for c in codes):
        return "poisoned"
    if any(OPEN_RESOLVER.match(c) for c in codes):
        return "blocked_resolver"
    if zone_kind == "policy":
        return "marked"
    if any(c in PBL_CODES for c in codes) and not any(
        (c.startswith("127.0.0.") and c not in PBL_CODES) for c in codes
    ):
        return "marked"
    if any(c.startswith("127.") for c in codes):
        return "listed"
    return "listed"


def run_dnsbl(ip, coffee=None, polite_delay=0.04):
    results = []
    poisoned = 0
    for zone, title, kind in DNSBL_ZONES:
        q = "%s.%s" % (_rev(ip), zone)
        codes, st = _doh_a(q)
        time.sleep(polite_delay)
        if st in ("doh_fail", "error") or codes is None:
            results.append({"zone": zone, "title": title, "status": "fail", "codes": []})
            continue
        if not codes:
            results.append({"zone": zone, "title": title, "status": "clean", "codes": []})
            continue
        kind_st = classify_dnsbl_codes(codes, kind)
        if kind_st == "poisoned":
            poisoned += 1
        results.append({"zone": zone, "title": title, "status": kind_st, "codes": codes})

    note = "DNSBL 经 DoH（dns.google）查询，避开本机 Clash fake-ip；Spamhaus 对部分公共解析器会返回拒绝码，已不计为有效"
    if poisoned >= 5:
        results = [r for r in results if r["status"] != "poisoned"]
        note = "检测到 fake-ip 污染，已丢弃被污染结果；" + note

    def _count(st):
        return sum(1 for r in results if r["status"] == st)

    valid = [r for r in results if r["status"] in ("clean", "marked", "listed")]
    summary = {
        "total_valid": len(valid),
        "clean": _count("clean"),
        "marked": _count("marked"),
        "listed": _count("listed"),
        "failed": _count("fail") + _count("blocked_resolver"),
        "note": note,
        "rows": results,
        "coffee_hits": (coffee or {}).get("_dnsbl_hits") or [],
        "coffee_pbl": (coffee or {}).get("_dnsbl_pbl") or [],
    }
    if coffee and coffee.get("_dnsbl_ok"):
        if coffee.get("_dnsbl_pbl") and summary["marked"] == 0:
            summary["marked"] += len(coffee["_dnsbl_pbl"])
        if coffee.get("_dnsbl_hits"):
            # coffee 服务端黑名单优先并入（DoH 可能查不到 Spamhaus）
            summary["listed"] = max(summary["listed"], len(coffee["_dnsbl_hits"]))
        if summary["total_valid"] < 12:
            extra_clean = 12 - len(coffee.get("_dnsbl_hits") or []) - len(coffee.get("_dnsbl_pbl") or [])
            summary["clean"] = max(summary["clean"], max(0, extra_clean))
            summary["total_valid"] = max(summary["total_valid"], 12)
        # 若 DoH 没标 PBL 但 coffee 有
        if coffee.get("_dnsbl_pbl"):
            summary["marked"] = max(summary["marked"], len(coffee["_dnsbl_pbl"]))
            summary["total_valid"] = max(summary["total_valid"], summary["clean"] + summary["marked"] + summary["listed"])
    return summary

def _curl(args, timeout=15, cfg=None):
    cmd = ["curl", "-sS", "-L", "--max-time", str(timeout), "-A", UA]
    if cfg:
        cmd += ["--config", cfg]
    cmd += args
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 3,
        )
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out, err
    except Exception as e:
        return 99, "", str(e)


def detect_exit_ip(cfg=None):
    last = "empty"
    for url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"):
        rc, out, err = _curl([url], timeout=8, cfg=cfg)
        ip = (out or "").strip().split()[0] if out else ""
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return ip, None
        last = err or "empty"
    return None, last


def _region_from(text, patterns):
    if not text:
        return None
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def _dns_method(host):
    try:
        socket.setdefaulttimeout(4)
        infos = socket.getaddrinfo(host, 443, socket.AF_INET)
        ips = sorted({x[4][0] for x in infos})
    except Exception:
        return "—"
    if not ips:
        return "—"
    for ip in ips:
        o = ip.split(".")
        try:
            a, b = int(o[0]), int(o[1])
        except (ValueError, IndexError):
            continue
        if a in (10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or (a == 100 and 64 <= b <= 127) or (a == 198 and 18 <= b <= 19):
            return "DNS"
    return "原生"


def check_tiktok(cfg=None):
    rc, out, err = _curl(["https://www.tiktok.com/"], timeout=12, cfg=cfg)
    region = _region_from(out, [r'"region"\s*:\s*"([A-Z]{2})"'])
    method = _dns_method("tiktok.com")
    if region:
        return {"name": "TikTok", "status": "解锁", "region": region, "method": method}
    if rc != 0 and not out:
        return {"name": "TikTok", "status": "失败", "region": "—", "method": "—"}
    return {"name": "TikTok", "status": "失败", "region": "—", "method": "—"}


def check_netflix(cfg=None):
    method = _dns_method("netflix.com")
    pages = []
    for title in ("81280792", "70143836"):
        rc, out, err = _curl(["https://www.netflix.com/title/%s" % title], timeout=12, cfg=cfg)
        pages.append((rc, out or ""))
    if all((not p[1] and p[0] != 0) for p in pages):
        return {"name": "Netflix", "status": "失败", "region": "—", "method": "—"}
    texts = [p[1] for p in pages]
    region = None
    for t in texts:
        region = _region_from(t, [r'"id"\s*:\s*"([A-Z]{2})"\s*,\s*"countryName"'])
        if region:
            break
    oh = [("Oh no!" in t) for t in texts if t]
    if oh and all(oh):
        return {"name": "Netflix", "status": "仅自制", "region": region or "—", "method": method}
    if any(t and "Oh no!" not in t for t in texts):
        return {"name": "Netflix", "status": "解锁", "region": region or "—", "method": method}
    return {"name": "Netflix", "status": "屏蔽", "region": "—", "method": "—"}


def check_youtube(cfg=None):
    method = _dns_method("www.youtube.com")
    rc, out, err = _curl(["-H", "Accept-Language: en", "https://www.youtube.com/premium"], timeout=12, cfg=cfg)
    if rc != 0 and not out:
        return {"name": "YouTube", "status": "失败", "region": "—", "method": "—"}
    if "www.google.cn" in (out or ""):
        return {"name": "YouTube", "status": "中国", "region": "CN", "method": "—"}
    if "Premium is not available in your country" in (out or ""):
        return {"name": "YouTube", "status": "禁会员", "region": "—", "method": "—"}
    region = _region_from(out or "", [r'"contentRegion"\s*:\s*"([A-Z]{2})"'])
    if "ad-free" in (out or "") or region:
        return {"name": "YouTube", "status": "解锁", "region": region or "—", "method": method}
    return {"name": "YouTube", "status": "失败", "region": "—", "method": "—"}


def check_amazon(cfg=None):
    method = _dns_method("www.primevideo.com")
    rc, out, err = _curl(["https://www.primevideo.com"], timeout=12, cfg=cfg)
    if rc != 0 and not out:
        return {"name": "AmazonPV", "status": "失败", "region": "—", "method": "—"}
    region = _region_from(out or "", [r'"currentTerritory"\s*:\s*"([A-Z]{2})"'])
    if region:
        return {"name": "AmazonPV", "status": "解锁", "region": region, "method": method}
    return {"name": "AmazonPV", "status": "屏蔽", "region": "—", "method": "—"}


def check_reddit(cfg=None):
    method = _dns_method("reddit.com")
    rc, out, err = _curl(
        ["-o", "/dev/null", "-w", "%{http_code}", "https://www.reddit.com/svc/shreddit/reddit-chat"],
        timeout=12, cfg=cfg,
    )
    code = (out or "").strip().split()[-1] if out else "000"
    if code == "200":
        return {"name": "Reddit", "status": "解锁", "region": "—", "method": method}
    if code == "403":
        return {"name": "Reddit", "status": "屏蔽", "region": "—", "method": "—"}
    return {"name": "Reddit", "status": "失败", "region": "—", "method": "—"}


def check_chatgpt(cfg=None):
    method = _dns_method("chat.openai.com")
    rc1, out1, _ = _curl(
        ["https://api.openai.com/compliance/cookie_requirements",
         "-H", "content-type: application/json"],
        timeout=10, cfg=cfg,
    )
    rc2, out2, _ = _curl(["https://ios.chat.openai.com/"], timeout=10, cfg=cfg)
    rc3, out3, _ = _curl(["https://chat.openai.com/cdn-cgi/trace"], timeout=8, cfg=cfg)
    loc = None
    if out3:
        m = re.search(r"^loc=([A-Z]{2})\s*$", out3, re.M)
        if m:
            loc = m.group(1)
    unsupported = "unsupported_country" in (out1 or "")
    vpn = "VPN" in (out2 or "")
    if rc1 != 0 and rc2 != 0 and not out1 and not out2:
        return {"name": "ChatGPT", "status": "失败", "region": loc or "—", "method": "—"}
    if unsupported and vpn:
        return {"name": "ChatGPT", "status": "屏蔽", "region": "—", "method": "—"}
    if unsupported and not vpn:
        return {"name": "ChatGPT", "status": "仅APP", "region": loc or "—", "method": method}
    if (not unsupported) and vpn:
        return {"name": "ChatGPT", "status": "仅网页", "region": loc or "—", "method": method}
    if not unsupported:
        return {"name": "ChatGPT", "status": "解锁", "region": loc or "—", "method": method}
    return {"name": "ChatGPT", "status": "失败", "region": loc or "—", "method": "—"}




def fmt_vote(n):
    """投票数展示：整数不带小数，半票写成 3.5。"""
    if n is None or n == "?":
        return "?"
    try:
        x = float(n)
    except (TypeError, ValueError):
        return str(n)
    if abs(x - round(x)) < 1e-9:
        return str(int(round(x)))
    s = ("%.2f" % x).rstrip("0").rstrip(".")
    return s


def is_manual_voter(title):
    return "手动" in (title or "")


def weight_type_votes(type_voters):
    """手动库类型票常来自同一上游，故每票 0.5，总权重不超过实时源，净贡献不超过 ±2。

    type_voters: iterable of (title, vote, note)，vote 为 'res' 或 'host'。
    返回 residential/hosting（加权后）及 live/manual 分解。
    """
    live_res = live_host = 0
    man_res = man_host = 0
    for item in type_voters or []:
        if not item:
            continue
        title = item[0] if not isinstance(item, dict) else (item.get("title") or item.get("source"))
        vote = item[1] if not isinstance(item, dict) else item.get("vote")
        if vote == "res":
            if is_manual_voter(title):
                man_res += 1
            else:
                live_res += 1
        elif vote == "host":
            if is_manual_voter(title):
                man_host += 1
            else:
                live_host += 1
    live_n = live_res + live_host
    w_res, w_host = man_res * 0.5, man_host * 0.5
    total_w = w_res + w_host
    if live_n > 0 and total_w > live_n:
        scale = float(live_n) / total_w
        w_res *= scale
        w_host *= scale
    net = w_res - w_host
    if net > 2:
        w_res = w_host + 2
    elif net < -2:
        w_host = w_res + 2
    return {
        "residential": live_res + w_res,
        "hosting": live_host + w_host,
        "live_residential": live_res,
        "live_hosting": live_host,
        "manual_residential": w_res,
        "manual_hosting": w_host,
        "manual_raw": {"residential": man_res, "hosting": man_host},
    }


def is_cloudflare_challenge(headers="", body="", err=""):
    hdr = headers or ""
    if re.search(r"(?im)^cf-mitigated\s*:", hdr) or re.search(r"(?i)cf-mitigated\s*:", hdr):
        return True
    blob = "\n".join([hdr, body or "", err or ""]).lower()
    if "just a moment" in blob:
        return True
    if "challenge-platform" in blob or "cdn-cgi/challenge-platform" in blob:
        return True
    return False


def is_claude_region_block(body="", url=""):
    blob = ((body or "") + "\n" + (url or "")).lower()
    markers = (
        "app-unavailable-in-region",
        "unavailable-in-region",
        "not available in your country",
        "isn't available in your country",
        "is not available in your country",
        "unsupported-country",
        "unsupported_country",
    )
    return any(s in blob for s in markers)


def _path_has_segment(url, segment):
    if not url:
        return False
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path or ""
    except Exception:
        path = url
    parts = [p for p in path.lower().split("/") if p]
    return segment.lower() in parts


def is_gemini_region_block(body="", url=""):
    """不要用 UnavailableSurface-*.js 这类文件名当屏蔽。"""
    blob = (body or "").lower()
    url_l = (url or "").lower()
    phrases = (
        "not available in your country",
        "isn't available in your country",
        "is not available in your country",
        "unavailable in your country",
        "country_unavailable",
        "gemini is not available",
    )
    if any(s in blob or s in url_l for s in phrases):
        return True
    # 仅当生效 URL 的路径段就是 unavailable，而不是 JS 文件名
    if _path_has_segment(url, "unavailable"):
        return True
    return False


def _is_public_ipv4(ip):
    try:
        o = [int(x) for x in str(ip).split(".")]
        if len(o) != 4 or any(x < 0 or x > 255 for x in o):
            return False
    except (TypeError, ValueError):
        return False
    a, b = o[0], o[1]
    if a == 0 or a == 127 or a >= 224:
        return False
    if a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if a == 198 and 18 <= b <= 19:
        return False
    return True


def list_local_ipv4():
    ips = []
    found = set()

    def _add(ip):
        if ip and ip not in found and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            found.add(ip)
            ips.append(ip)

    for cmd in (
        ["ip", "-4", "-o", "addr", "show"],
        ["ifconfig", "-a"],
        ["hostname", "-I"],
    ):
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
            text = p.stdout.decode("utf-8", "replace") if p.returncode == 0 else ""
        except Exception:
            text = ""
        if not text:
            continue
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
            _add(m.group(1))
        if ips and cmd[0] in ("ip", "ifconfig"):
            break
    try:
        host = socket.gethostname()
        for item in socket.getaddrinfo(host, None, socket.AF_INET):
            _add(item[4][0])
    except Exception:
        pass
    return ips


def should_test_local_port25():
    """本机 25 端口探测只在真正的公网 VPS 上有意义；macOS 或接口上没有公网 IPv4 则不测。"""
    if sys.platform == "darwin":
        return False
    return any(_is_public_ipv4(ip) for ip in list_local_ipv4())




def _curl_http(url, timeout=12, cfg=None, extra=None):
    """GET url，同时拿状态码、生效 URL、响应头和正文。"""
    fd, hpath = tempfile.mkstemp(prefix="ipcheck-hdr-")
    os.close(fd)
    try:
        args = list(extra or [])
        args += ["-D", hpath, "-w", "\n__HTTP__:%{http_code} %{url_effective}", url]
        rc, out, err = _curl(args, timeout=timeout, cfg=cfg)
        body = out or ""
        code, final = "000", url
        m = re.search(r"\n__HTTP__:(\d{3})\s+(\S+)\s*$", body)
        if m:
            code, final = m.group(1), m.group(2)
            body = body[:m.start()]
        try:
            headers = open(hpath, encoding="utf-8", errors="replace").read()
        except OSError:
            headers = ""
        return {"rc": rc, "code": code, "url": final, "headers": headers, "body": body, "err": err or ""}
    finally:
        try:
            os.remove(hpath)
        except OSError:
            pass


def check_claude(cfg=None):
    """Claude 地理可用性。Cloudflare 挑战的 403 记「未知」，只有明确区域不可用才算屏蔽。"""
    method = _dns_method("claude.ai")
    login = _curl_http("https://claude.ai/login", timeout=12, cfg=cfg)
    home = _curl_http("https://claude.ai/", timeout=12, cfg=cfg)
    # 区域封锁证据优先
    if is_claude_region_block(home.get("body"), home.get("url")):
        res = home
    elif is_claude_region_block(login.get("body"), login.get("url")):
        res = login
    elif home.get("code", "").startswith(("2", "3")) and not is_cloudflare_challenge(
        home.get("headers"), home.get("body"), home.get("err")
    ):
        res = home
    else:
        res = login
    body, url, headers, err, code, rc = (
        res.get("body") or "", res.get("url") or "", res.get("headers") or "",
        res.get("err") or "", res.get("code") or "000", res.get("rc"),
    )
    if is_claude_region_block(body, url):
        return {"name": "Claude", "status": "屏蔽", "region": "—", "method": "—"}
    api = _curl_http("https://api.anthropic.com/", timeout=8, cfg=cfg)
    api_reachable = (api.get("code") == "405")
    cf = (
        is_cloudflare_challenge(headers, body, err)
        or is_cloudflare_challenge(login.get("headers"), login.get("body"), login.get("err"))
        or is_cloudflare_challenge(home.get("headers"), home.get("body"), home.get("err"))
    )
    if cf or (code == "403" and ("cloudflare" in (headers + body + err).lower() or cf)):
        return {
            "name": "Claude", "status": "未知（Cloudflare 挑战）", "region": "—", "method": "—",
            "note": "api.anthropic.com 可达" if api_reachable else None,
        }
    if code == "403":
        return {"name": "Claude", "status": "未知", "region": "—", "method": "—"}
    if code.startswith("2") or code.startswith("3"):
        return {"name": "Claude", "status": "解锁", "region": "—", "method": method}
    if api_reachable:
        return {"name": "Claude", "status": "未知", "region": "—", "method": "—", "note": "api.anthropic.com 可达"}
    if rc != 0 and code in ("000",):
        return {"name": "Claude", "status": "失败", "region": "—", "method": "—"}
    return {"name": "Claude", "status": "失败", "region": "—", "method": "—"}


def check_gemini(cfg=None):
    """Gemini 地理可用性。不把 UnavailableSurface-*.js 这类文件名当成屏蔽。"""
    method = _dns_method("gemini.google.com")
    res = _curl_http("https://gemini.google.com/app", timeout=12, cfg=cfg)
    if not (res.get("body") or res.get("code") not in ("000", None, "")):
        res = _curl_http("https://gemini.google.com/", timeout=12, cfg=cfg)
    body, url, headers, err, code, rc = (
        res.get("body") or "", res.get("url") or "", res.get("headers") or "",
        res.get("err") or "", res.get("code") or "000", res.get("rc"),
    )
    if is_gemini_region_block(body, url):
        return {"name": "Gemini", "status": "屏蔽", "region": "—", "method": "—"}
    if is_cloudflare_challenge(headers, body, err):
        return {"name": "Gemini", "status": "未知（Cloudflare 挑战）", "region": "—", "method": "—"}
    if code == "403":
        return {"name": "Gemini", "status": "未知", "region": "—", "method": "—"}
    if rc != 0 and code in ("000",):
        return {"name": "Gemini", "status": "失败", "region": "—", "method": "—"}
    if code.startswith("2") or code.startswith("3"):
        return {"name": "Gemini", "status": "解锁", "region": "—", "method": method}
    return {"name": "Gemini", "status": "未知", "region": "—", "method": "—"}


def check_disney(cfg=None):
    # 精简探测：看主站是否跳到不可用页 / 能否打开
    method = _dns_method("disneyplus.com")
    rc, out, err = _curl(["-o", "/dev/null", "-w", "%{http_code} %{url_effective}", "https://www.disneyplus.com"], timeout=12, cfg=cfg)
    text = (out or "").strip()
    parts = text.split()
    code = parts[0] if parts else "000"
    url = parts[1] if len(parts) > 1 else ""
    if code in ("000",) or (rc != 0 and not text):
        return {"name": "Disney+", "status": "失败", "region": "—", "method": "—"}
    if "unavailable" in url or "preview" in url and "unavailable" in url:
        return {"name": "Disney+", "status": "屏蔽", "region": "—", "method": "—"}
    if "access-denied" in url or "/blocked" in url:
        return {"name": "Disney+", "status": "屏蔽", "region": "—", "method": "—"}
    # 无法稳定拿到地区时：能打开主站记解锁，地区 —
    if code.startswith("2") or code.startswith("3"):
        return {"name": "Disney+", "status": "解锁", "region": "—", "method": method}
    return {"name": "Disney+", "status": "失败", "region": "—", "method": "—"}


def check_remote25(cfg=None):
    host = "gmail-smtp-in.l.google.com"
    if cfg:
        rc, out, err = _curl(
            ["-o", "/dev/null", "-w", "%{http_code}:%{time_connect}", "telnet://%s:25" % host],
            timeout=10, cfg=cfg,
        )
        if rc == 0 or "Connected" in (err or "") or "220" in (out or "") or "220" in (err or ""):
            return "可达"
        return "不可达"
    try:
        socket.setdefaulttimeout(8)
        s = socket.create_connection((host, 25), 8)
        data = s.recv(256).decode("utf-8", "replace")
        s.close()
        return "可达" if "220" in data else "不可达"
    except Exception:
        return "不可达"


def check_local25():
    if not should_test_local_port25():
        return "仅 VPS 上可测"
    return check_remote25(cfg=None)


def run_unlock(target_ip, mode, cfg_path=None):
    services_empty = [
        {"name": n, "status": "未测", "region": "—", "method": "—"}
        for n in UNLOCK_SERVICES
    ]
    if mode == "bare":
        return {
            "tested": False,
            "reason": "未测（需 --proxy 或在该 IP 的机器上运行）",
            "exit_ip": None,
            "exit_match": None,
            "services": services_empty,
        }
    cfg = cfg_path if (mode == "proxy" and cfg_path and os.path.isfile(cfg_path)) else None
    exit_ip, err = detect_exit_ip(cfg=cfg)
    match = bool(exit_ip and exit_ip == target_ip)
    if not exit_ip:
        return {
            "tested": False,
            "reason": "出口探测失败（%s），未跑解锁" % _dash(err),
            "exit_ip": None,
            "exit_match": False,
            "services": services_empty,
        }
    warning = None
    if not match:
        warning = "出口 IP %s 与目标 %s 不匹配，解锁结果不能代表目标 IP" % (exit_ip, target_ip)
    checks = [check_tiktok, check_disney, check_netflix, check_youtube, check_amazon,
              check_reddit, check_chatgpt, check_claude, check_gemini]
    services = []
    pretty = {
        "tiktok": "TikTok", "disney": "Disney+", "netflix": "Netflix",
        "youtube": "YouTube", "amazon": "AmazonPV", "reddit": "Reddit",
        "chatgpt": "ChatGPT", "claude": "Claude", "gemini": "Gemini",
    }
    for fn in checks:
        try:
            services.append(fn(cfg=cfg))
        except Exception:
            services.append({"name": pretty.get(fn.__name__.replace("check_", ""), "?"), "status": "失败", "region": "—", "method": "—"})
    return {
        "tested": True,
        "reason": warning,
        "exit_ip": exit_ip,
        "exit_match": match,
        "services": services,
        "warning": warning,
    }

def _first(*vals):
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s and s.lower() not in ("none", "null", "n/a", "na", "?", "-"):
            return s
    return None


def _src_ok(sources, name):
    return bool((sources.get(name) or {}).get("ok"))


def build_basic(sources, extras, meta):
    coffee = (sources.get("coffee") or {}).get("_coffee") if _src_ok(sources, "coffee") else None
    ipinfo = sources.get("ipinfo") if _src_ok(sources, "ipinfo") else None
    who = (extras.get("ipwho") or {}).get("data") or {}
    dbip = (extras.get("dbip") or {}).get("data") or {}
    i2 = (extras.get("ip2location") or {}).get("data") or {}
    iapi = (extras.get("ipapi_is") or {}).get("data") or {}
    who_conn = who.get("connection") if isinstance(who.get("connection"), dict) else {}
    who_tz = who.get("timezone") if isinstance(who.get("timezone"), dict) else {}

    city = _first(
        ipinfo.get("city") if ipinfo else None,
        (coffee or {}).get("city"),
        i2.get("city_name"),
        iapi.get("city"),
        who.get("city"),
        dbip.get("city"),
    )
    region = _first(
        i2.get("region_name"),
        iapi.get("region"),
        who.get("region"),
        dbip.get("stateProv"),
        (coffee or {}).get("region"),
    )
    lat = _first(i2.get("latitude"), iapi.get("lat"), who.get("latitude"))
    lon = _first(i2.get("longitude"), iapi.get("lon"), who.get("longitude"))
    loc = "%s, %s" % (lat, lon) if lat and lon else (ipinfo.get("raw_loc") if ipinfo else None)

    asn = _first(
        (coffee or {}).get("asn"),
        i2.get("asn"),
        who_conn.get("asn"),
        iapi.get("asn"),
        ipinfo.get("asn") if ipinfo else None,
    )
    org = _first(
        (coffee or {}).get("asname") or (coffee or {}).get("asOrganization") or (coffee or {}).get("company_name"),
        i2.get("as"),
        who_conn.get("isp") or who_conn.get("org"),
        ipinfo.get("org") if ipinfo else None,
    )
    asn_s = _dash(asn)
    if asn_s != "—":
        m = re.search(r"(AS)?(\d+)", str(asn_s), re.I)
        if m:
            name = str(asn_s)[m.end():].strip(" -")
            asn_s = "AS" + m.group(2) + ((" " + name) if name else "")
    tz = _first(
        ipinfo.get("timezone") if ipinfo else None,
        iapi.get("timezone") if not isinstance(iapi.get("timezone"), dict) else None,
        who_tz.get("id"),
        i2.get("time_zone"),
    )
    usage_cc = _first((coffee or {}).get("countryCode"), i2.get("country_code"), who.get("country_code"), dbip.get("countryCode"), ipinfo.get("country") if ipinfo else None, iapi.get("country"))
    usage_name = _first((coffee or {}).get("country"), i2.get("country_name"), who.get("country"), dbip.get("countryName"), iapi.get("country"))
    reg_cc = _first((coffee or {}).get("registered_country_code"))
    reg_name = _first((coffee or {}).get("registered_country"))
    ip_type = "—"
    if _src_ok(sources, "ipx") or _src_ok(sources, "iping") or _src_ok(sources, "coffee"):
        if sources.get("ipx", {}).get("_broadcast") or sources.get("iping", {}).get("_broadcast") or sources.get("coffee", {}).get("_broadcast_hint"):
            ip_type = "广播"
        else:
            ip_type = "原生"
    if city and region and region.lower() not in city.lower():
        city_s = "%s, %s" % (city, region)
    else:
        city_s = city or region or "—"
    if usage_cc and usage_name and str(usage_cc).lower() not in str(usage_name).lower():
        usage_s = "[%s] %s" % (str(usage_cc).upper(), usage_name)
    else:
        usage_s = usage_name or (str(usage_cc).upper() if usage_cc else "—")
    if reg_cc and reg_name:
        reg_s = "[%s] %s" % (str(reg_cc).upper(), reg_name)
    else:
        reg_s = reg_name or "—"
    return {
        "asn": asn_s,
        "org": _dash(org),
        "location": _dash(loc),
        "city": city_s,
        "usage_country": usage_s,
        "registered_country": reg_s,
        "timezone": _dash(tz),
        "ip_type": ip_type,
    }


def _row_type(db, usage, company, status, note=None):
    return {"db": db, "usage": usage or "—", "company": company or "—", "status": status, "note": note}


def build_types(sources, extras, key_status, manual_db=None):
    rows = []
    if key_status.get("ipinfo_paid"):
        d = (extras.get("ipinfo_full") or {}).get("data") or {}
        asn = d.get("asn") if isinstance(d.get("asn"), dict) else {}
        com = d.get("company") if isinstance(d.get("company"), dict) else {}
        rows.append(_row_type("IPinfo", classify_type(asn.get("type")) or "—", classify_type(com.get("type")) or "—", "ok"))
    else:
        rows.append(_row_type("IPinfo", "未配置", "未配置", "no_key", "需 IPINFO_TOKEN（付费层才有类型字段）"))
    if key_status.get("ipregistry"):
        d = (extras.get("ipregistry") or {}).get("data") or {}
        conn, com = d.get("connection") or {}, d.get("company") or {}
        rows.append(_row_type("ipregistry", classify_type(conn.get("type")) or "—", classify_type(com.get("type")) or "—", "ok"))
    else:
        rows.append(_row_type("ipregistry", "未配置", "未配置", "no_key", "需 IPREGISTRY_KEY"))
    if key_status.get("ipapi_is"):
        d = (extras.get("ipapi_is") or {}).get("data") or {}
        asn = d.get("asn") if isinstance(d.get("asn"), dict) else {}
        com = d.get("company") if isinstance(d.get("company"), dict) else {}
        rows.append(_row_type("ipapi", classify_type((asn or {}).get("type")) or "—", classify_type((com or {}).get("type")) or "—", "ok"))
    else:
        rows.append(_row_type("ipapi", "未配置", "未配置", "limited_free", "ipapi.is 免费层无类型字段，需 IPAPI_IS_KEY"))
    i2 = (extras.get("ip2location") or {}).get("data") or {}
    if i2 and (i2.get("usage_type") or (i2.get("as_info") or {}).get("as_usage_type")):
        asinfo = i2.get("as_info") or {}
        rows.append(_row_type("IP2Location", classify_type(i2.get("usage_type")) or "—", classify_type(asinfo.get("as_usage_type")) or "—", "ok"))
    elif key_status.get("ip2location"):
        rows.append(_row_type("IP2Location", "—", "—", "no_field", "已配置 key 但响应无 usage_type"))
    else:
        rows.append(_row_type("IP2Location", "未配置", "未配置", "no_key", "免费层无 usage_type，需 IP2LOCATION_KEY"))
    ab = sources.get("abuseipdb") or {}
    if ab.get("enabled") and ab.get("ok"):
        rows.append(_row_type("AbuseIPDB", classify_type(ab.get("_usage") or ab.get("usageType")) or "—", "—", "ok"))
    else:
        rows.append(_row_type("AbuseIPDB", "未配置", "—", "no_key", "需 ABUSEIPDB_KEY"))
    if _src_ok(sources, "iplogs"):
        zh = {"res": "家宽", "host": "机房"}.get(sources["iplogs"].get("type_vote"), "—")
        rows.append(_row_type("IPLogs", zh, "—", "ok"))
    if _src_ok(sources, "coffee"):
        d = sources["coffee"].get("_coffee") or {}
        if d.get("isResidential"):
            u = "家宽"
        elif d.get("is_datacenter"):
            u = "机房"
        else:
            u = classify_type(d.get("company_type")) or "—"
        rows.append(_row_type("ip.net.coffee", u, classify_type(d.get("company_type")) or "—", "ok"))
    if _src_ok(sources, "scamalytics"):
        sv = str(sources["scamalytics"].get("_server") or "").lower()
        u = "机房" if sv in ("yes", "true", "1") else ("家宽" if sv in ("no", "false", "0") else "—")
        rows.append(_row_type("Scamalytics", u, "—", "ok", "公开页 Server 标志"))
    if _src_ok(sources, "ipx"):
        zh = {"res": "家宽", "host": "机房"}.get(sources["ipx"].get("type_vote"), "—")
        rows.append(_row_type("ipx.al", zh, "—", "ok"))
    if _src_ok(sources, "iping"):
        zh = {"res": "家宽", "host": "机房"}.get(sources["iping"].get("type_vote"), "—")
        rows.append(_row_type("iping.cc", zh, "—", "ok"))
    return apply_manual_types(rows, manual_db)


def build_scores(sources, extras, key_status, manual_db=None):
    rows = []
    i2 = (extras.get("ip2location") or {}).get("data") or {}
    if i2 and i2.get("fraud_score") is not None:
        sc = i2.get("fraud_score")
        rows.append({"db": "IP2Location", "score": sc, "level": ip2_level(sc) or "—", "status": "ok"})
    else:
        rows.append({"db": "IP2Location", "score": None, "level": "未配置", "status": "no_key"})
    scs = sources.get("scamalytics") or {}
    if scs.get("ok") and scs.get("_score") is not None:
        sc = scs["_score"]
        rows.append({"db": "Scamalytics", "score": sc, "level": scam_level(sc) or "—", "status": "ok"})
    else:
        rows.append({"db": "Scamalytics", "score": None, "level": "—", "status": "fail"})
    if key_status.get("ipapi_is"):
        d = (extras.get("ipapi_is") or {}).get("data") or {}
        com = d.get("company") or {}
        raw = com.get("abuser_score") or d.get("abuser_score")
        rows.append({"db": "ipapi", "score": raw, "level": _dash(raw), "status": "ok"})
    else:
        rows.append({"db": "ipapi", "score": None, "level": "未配置", "status": "no_key", "note": "需 IPAPI_IS_KEY"})
    if _src_ok(sources, "coffee"):
        raw = (sources["coffee"].get("_coffee") or {}).get("abuser_score")
        level = None
        if raw is not None:
            m = re.search(r"\(([^)]+)\)", str(raw))
            mapping = {"very low": "极低风险", "low": "低风险", "elevated": "较高风险", "high": "高风险", "very high": "极高风险"}
            if m:
                level = mapping.get(m.group(1).strip().lower(), m.group(1))
        rows.append({"db": "ip.net.coffee", "score": raw, "level": level or "—", "status": "ok", "note": "abuser_score"})
    ab = sources.get("abuseipdb") or {}
    if ab.get("enabled") and ab.get("ok") and ab.get("_abuse_score") is not None:
        sc = ab["_abuse_score"]
        rows.append({"db": "AbuseIPDB", "score": sc, "level": abuse_level(sc) or "—", "status": "ok"})
    else:
        rows.append({"db": "AbuseIPDB", "score": None, "level": "未配置", "status": "no_key"})
    ipqs_ex = extras.get("ipqs") or {}
    insp = inspect_ipqs(ipqs_ex.get("data"), ipqs_ex.get("http")) if key_status.get("ipqs") else None
    if insp and insp.get("ok"):
        d = ipqs_ex.get("data") or {}
        sc = d.get("fraud_score")
        rows.append({"db": "IPQS", "score": sc, "level": ipqs_level(sc) or "—", "status": "ok"})
    elif insp and insp.get("status") == "no_credits":
        rows.append({"db": "IPQS", "score": None, "level": "不可用（额度不足）", "status": "no_credits",
                     "note": "接口已配置但额度不足，不计入分数、不视为失败"})
    elif key_status.get("ipqs"):
        reason = (insp or {}).get("reason") or "不可用"
        rows.append({"db": "IPQS", "score": None, "level": reason, "status": (insp or {}).get("status") or "fail"})
    else:
        rows.append({"db": "IPQS", "score": None, "level": "未配置", "status": "no_key"})
    d = (extras.get("dbip") or {}).get("data") or {}
    if d and d.get("threatLevel"):
        rows.append({"db": "DB-IP", "score": d.get("threatLevel"), "level": dbip_level(d.get("threatLevel")) or "—", "status": "ok"})
    else:
        rows.append({"db": "DB-IP", "score": None, "level": "未配置", "status": "no_key", "note": "免费层无 threatLevel"})
    return apply_manual_scores(rows, manual_db, extras)

def _factor(db, region=None, proxy=None, tor=None, vpn=None, server=None, abuser=None, robot=None, independent=True, note=None, status="ok"):
    unset = "未配置" if status == "no_key" else ("—" if status != "ok" else None)
    def cell(v):
        if unset is not None:
            return unset
        return _bool_zh(v)
    return {
        "db": db,
        "region": region if region not in (None, "") else "—",
        "proxy": cell(proxy), "tor": cell(tor), "vpn": cell(vpn),
        "server": cell(server), "abuser": cell(abuser), "robot": cell(robot),
        "independent": independent, "note": note, "status": status,
    }


def _cc(v):
    if not v or v in ("—", "未配置"):
        return v or "—"
    s = str(v).strip()
    return s.upper() if len(s) == 2 else s


def build_factors(sources, extras, key_status, manual_db=None):
    rows = []
    i2 = (extras.get("ip2location") or {}).get("data") or {}
    if i2 and (i2.get("is_proxy") is not None or i2.get("proxy") or i2.get("usage_type")):
        px = i2.get("proxy") if isinstance(i2.get("proxy"), dict) else {}
        rows.append(_factor(
            "IP2Location", region=i2.get("country_code"),
            proxy=px.get("is_public_proxy") if px.get("is_public_proxy") is not None else i2.get("is_proxy"),
            tor=px.get("is_tor"), vpn=px.get("is_vpn"), server=px.get("is_data_center"),
            abuser=px.get("is_spammer"),
            robot=(px.get("is_web_crawler") or px.get("is_scanner") or px.get("is_botnet")) if px else None,
            independent=True, note="免费层通常仅有 is_proxy" if not px else None,
        ))
    else:
        rows.append(_factor("IP2Location", status="no_key", independent=False, note="需 IP2LOCATION_KEY 才有完整因子"))
    if key_status.get("ipapi_is"):
        d = (extras.get("ipapi_is") or {}).get("data") or {}
        loc = d.get("location") or {}
        rows.append(_factor("ipapi", region=loc.get("country_code") or d.get("country"),
            proxy=d.get("is_proxy"), tor=d.get("is_tor"), vpn=d.get("is_vpn"),
            server=d.get("is_datacenter"), abuser=d.get("is_abuser"), robot=d.get("is_crawler"), independent=True))
    else:
        rows.append(_factor("ipapi", status="no_key", independent=False))
    if key_status.get("ipregistry"):
        d = (extras.get("ipregistry") or {}).get("data") or {}
        sec, loc = d.get("security") or {}, d.get("location") or {}
        cc = loc.get("country_code")
        if isinstance(loc.get("country"), dict):
            cc = loc["country"].get("code") or cc
        rows.append(_factor("ipregistry", region=cc, proxy=sec.get("is_proxy"),
            tor=sec.get("is_tor") or sec.get("is_tor_exit"), vpn=sec.get("is_vpn"),
            server=sec.get("is_cloud_provider"), abuser=sec.get("is_abuser"), independent=True))
    else:
        rows.append(_factor("ipregistry", status="no_key", independent=False))
    ipqs_ex = extras.get("ipqs") or {}
    insp = inspect_ipqs(ipqs_ex.get("data"), ipqs_ex.get("http")) if key_status.get("ipqs") else None
    if insp and insp.get("ok"):
        d = ipqs_ex.get("data") or {}
        rows.append(_factor("IPQS", region=d.get("country_code"), proxy=d.get("proxy"),
            tor=d.get("tor"), vpn=d.get("vpn"), abuser=d.get("recent_abuse"), robot=d.get("bot_status"), independent=True))
    elif insp and insp.get("status") == "no_credits":
        rows.append(_factor("IPQS", status="no_credits", independent=False, note="不可用（额度不足）"))
    elif key_status.get("ipqs"):
        rows.append(_factor("IPQS", status="fail", independent=False,
                            note=(insp or {}).get("reason") or "不可用"))
    else:
        rows.append(_factor("IPQS", status="no_key", independent=False))
    if _src_ok(sources, "scamalytics"):
        sc = sources["scamalytics"]
        sv = str(sc.get("_server") or "").lower()
        server = True if sv in ("yes", "true", "1") else (False if sv in ("no", "false", "0") else None)
        # 公开页能解析到 Yes/No 时写明确布尔；列表仅含阳性标志，不能把空列表当成未知
        vpn = sc.get("_vpn")
        proxy = sc.get("_proxy")
        tor = sc.get("_tor")
        flags = sc.get("flags") or []
        if vpn is None and ("_vpn" not in sc):
            vpn = ("vpn" in flags) if (flags or sc.get("_server") is not None) else None
        if proxy is None and ("_proxy" not in sc):
            proxy = ("proxy" in flags) if (flags or sc.get("_server") is not None) else None
        if tor is None and ("_tor" not in sc):
            tor = ("tor" in flags) if (flags or sc.get("_server") is not None) else None
        row = _factor(
            "Scamalytics",
            vpn=vpn, proxy=proxy, tor=tor,
            server=server, independent=True,
            note="公开页面自身标志，非站内嵌套的第三方库",
        )
        rows.append(row)
    if key_status.get("ipdata"):
        d = (extras.get("ipdata") or {}).get("data") or {}
        th = d.get("threat") or {}
        rows.append(_factor("ipdata", region=d.get("country_code"), proxy=th.get("is_proxy"),
            tor=th.get("is_tor"), server=th.get("is_datacenter"),
            abuser=th.get("is_threat") or th.get("is_known_abuser") or th.get("is_known_attacker"), independent=True))
    else:
        rows.append(_factor("ipdata", status="no_key", independent=False))
    if key_status.get("ipinfo_paid"):
        d = (extras.get("ipinfo_full") or {}).get("data") or {}
        pr = d.get("privacy") or {}
        rows.append(_factor("IPinfo", region=d.get("country"), proxy=pr.get("proxy"),
            tor=pr.get("tor"), vpn=pr.get("vpn"), server=pr.get("hosting"), independent=True))
    else:
        rows.append(_factor("IPinfo", status="no_key", independent=False, note="免费层无 privacy 字段"))
    d = (extras.get("dbip") or {}).get("data") or {}
    if d and (d.get("isProxy") is not None or d.get("isCrawler") is not None):
        rows.append(_factor("DB-IP", region=d.get("countryCode"), proxy=d.get("isProxy"),
            robot=d.get("isCrawler"), independent=True, note="免费层字段有限"))
    else:
        rows.append(_factor("DB-IP", status="no_key", independent=False, note="免费层无威胁因子"))
    if _src_ok(sources, "iplogs"):
        s = sources["iplogs"]
        flags = s.get("flags") or []
        rows.append(_factor("IPLogs", region=s.get("country"),
            proxy="proxy" in flags, tor="tor" in flags, vpn="vpn" in flags,
            server=(s.get("type_vote") == "host"), independent=True))
    if _src_ok(sources, "coffee"):
        d = sources["coffee"].get("_coffee") or {}
        rows.append(_factor("ip.net.coffee", region=d.get("countryCode"),
            proxy=d.get("is_proxy"), tor=d.get("is_tor"), vpn=d.get("is_vpn"),
            server=d.get("is_datacenter"), abuser=d.get("is_abuser"), robot=d.get("is_crawler"), independent=True))
    if _src_ok(sources, "iping"):
        s = sources["iping"]
        flags = s.get("flags") or []
        rows.append(_factor("iping.cc", region=s.get("country"),
            proxy="proxy" in flags, server=(s.get("type_vote") == "host"), independent=True))
    return apply_manual_factors(rows, manual_db)


def empty_unlock():
    return {
        "tested": False,
        "reason": "未测（需 --proxy 或在该 IP 的机器上运行）",
        "exit_ip": None, "exit_match": None,
        "services": [{"name": n, "status": "未测", "region": "—", "method": "—"}
                     for n in UNLOCK_SERVICES],
    }


def build_mail(mode, local25, remote25, dnsbl):
    if mode == "bare":
        local_s = "仅 VPS 上可测"
        remote_s = "未测（需 --proxy 或在该 IP 的机器上运行）"
    else:
        local_s = local25 if mode == "local" else "仅 VPS 上可测"
        remote_s = remote25 or "—"
    return {"local25": local_s, "remote25": remote_s, "dnsbl": dnsbl or {}}


def _format_hard_basic(hard):
    """Flatten hard-evidence into section-1 display fields."""
    hard = hard or {}
    reg = hard.get("registry") or {}
    rdns = hard.get("rdns") or {}
    flags = hard.get("flags") or {}
    org = reg.get("org") or "—"
    parts = []
    if reg.get("cidr"):
        parts.append(reg["cidr"])
    if reg.get("netname"):
        parts.append(reg["netname"])
    if reg.get("handle"):
        parts.append(reg["handle"])
    net = "  ".join(parts) if parts else "—"
    alloc = "—"
    if reg.get("allocation"):
        alloc = reg["allocation"]
        if reg.get("allocation_zh"):
            alloc = "%s（%s）" % (reg["allocation"], reg["allocation_zh"])
        if flags.get("reassigned") and flags.get("mismatch"):
            alloc += "；转租/转分配"
    dates = []
    if reg.get("registered"):
        dates.append("登记 %s" % reg["registered"])
    if reg.get("updated"):
        dates.append("更新 %s" % reg["updated"])
    rdns_line = "—"
    if rdns.get("error") and not rdns.get("ptr"):
        rdns_line = "—"
    elif not rdns.get("ptr"):
        rdns_line = "无 PTR"
    else:
        bits = [rdns.get("ptr")]
        if rdns.get("style_zh"):
            bits.append(rdns["style_zh"])
        if rdns.get("fcrdns"):
            bits.append("FCrDNS")
        elif rdns.get("ptr"):
            bits.append("正反向不一致")
        rdns_line = "，".join(bits)
    return {
        "reg_org": org,
        "reg_net": net,
        "reg_alloc": alloc,
        "reg_country": reg.get("country") or "—",
        "reg_dates": "，".join(dates) if dates else "—",
        "rdns_line": rdns_line,
        "hard_summary": hard.get("summary") or "",
        "hard_evidence": hard,
    }


def build_report(ctx):
    sources = ctx["sources"]
    extras = ctx.get("extras") or {}
    key_status = ctx.get("key_status") or {}
    meta = ctx.get("meta") or {}
    basic = build_basic(sources, extras, meta)
    hard = ctx.get("hard") or ctx.get("hard_evidence") or {}
    basic.update(_format_hard_basic(hard))
    notes = ctx.get("notes") or ctx.get("manual_notes") or {}
    db = notes.get("db") if isinstance(notes, dict) and "db" in notes else (ctx.get("manual_db") or {})
    types = build_types(sources, extras, key_status, manual_db=db)
    scores = build_scores(sources, extras, key_status, manual_db=db)
    factors = build_factors(sources, extras, key_status, manual_db=db)
    mail = build_mail(ctx.get("mode") or "bare", ctx.get("local25"), ctx.get("remote25"), ctx.get("dnsbl"))
    mail = apply_manual_mail(mail, db)
    out = {
        "basic": basic,
        "types": types,
        "scores": scores,
        "factors": factors,
        "unlock": ctx.get("unlock") or empty_unlock(),
        "mail": mail,
        "hard_evidence": hard,
    }
    if notes_has_content(notes):
        out["manual_notes"] = {
            "updated": notes.get("updated"),
            "observed": notes.get("observed"),
            "source": "手动",
        }
    return out


def print_report(report, color=False):
    c = C(color)
    b = report.get("basic") or {}
    print()
    print("%s一、基础信息%s" % (c.bold, c.reset))
    print("  自治系统号： %s" % b.get("asn", "—"))
    print("  组织：       %s" % b.get("org", "—"))
    print("  坐标：       %s" % b.get("location", "—"))
    print("  城市：       %s" % b.get("city", "—"))
    print("  使用地：     %s" % b.get("usage_country", "—"))
    print("  注册地：     %s" % b.get("registered_country", "—"))
    print("  时区：       %s" % b.get("timezone", "—"))
    typ = b.get("ip_type") or "—"
    if typ == "原生":
        typ_s = (c.bg_green + " 原生IP " + c.reset) if c.on else typ
    elif typ == "广播":
        typ_s = (c.bg_red + " 广播IP " + c.reset) if c.on else typ
    else:
        typ_s = typ
    print("  IP类型：     %s" % typ_s)
    # 硬证据（登记库 + rDNS）
    print("  登记单位：   %s" % (b.get("reg_org") or "—"))
    net = b.get("reg_net") or "—"
    print("  网段：       %s" % net)
    print("  分配类型：   %s" % (b.get("reg_alloc") or "—"))
    print("  登记国家：   %s" % (b.get("reg_country") or "—"))
    print("  登记/更新：  %s" % (b.get("reg_dates") or "—"))
    print("  rDNS：       %s" % (b.get("rdns_line") or "—"))
    if b.get("hard_summary"):
        print("  硬证据：     %s" % b["hard_summary"].replace("硬证据: ", "", 1))

    print()
    print("%s二、IP类型属性%s" % (c.bold, c.reset))
    print("  %-16s %-10s %-10s %s" % ("数据库", "使用类型", "公司类型", "说明"))
    for r in report.get("types") or []:
        u, co = r.get("usage") or "—", r.get("company") or "—"
        if c.on:
            u_s, co_s = color_type(u, c), color_type(co, c)
        else:
            u_s, co_s = u, co
        print("  %-16s %-18s %-18s %s" % (r.get("db"), u_s, co_s, r.get("note") or ""))

    print()
    print("%s三、风险评分%s" % (c.bold, c.reset))
    print("  风险等级： 极低 低 / 中等 / 高 极高")
    for r in report.get("scores") or []:
        sc = r.get("score")
        sc_s = "—" if sc is None else str(sc)
        print("  %-16s %s    %s" % (r.get("db"), sc_s, color_level(r.get("level") or "—", c)))
        if r.get("note"):
            print("                   （%s）" % r["note"])

    print()
    print("%s四、风险因子%s" % (c.bold, c.reset))
    print("  %-16s %-16s %-4s %-4s %-4s %-6s %-4s %-6s" % ("库", "地区", "代理", "Tor", "VPN", "服务器", "滥用", "机器人"))
    for r in report.get("factors") or []:
        region = _cc(r.get("region")) if r.get("status") == "ok" else ("未配置" if r.get("status") == "no_key" else "—")
        def cb(k):
            v = r.get(k) or "—"
            return color_bool(v, c) if c.on else v
        print("  %-16s %-16s %-4s %-4s %-4s %-6s %-4s %-6s" % (
            r.get("db"), region, cb("proxy"), cb("tor"), cb("vpn"), cb("server"), cb("abuser"), cb("robot")))
    print("  说明：未配置表示该库需要 API key，未编造数据。Scamalytics 行来自公开页自身标志，不是其站内嵌套的第三方库。")

    print()
    print("%s五、流媒体及AI服务解锁检测%s" % (c.bold, c.reset))
    un = report.get("unlock") or empty_unlock()
    if un.get("reason"):
        print("  %s" % un["reason"])
    if un.get("exit_ip"):
        print("  出口 IP：%s（%s）" % (un["exit_ip"], "匹配" if un.get("exit_match") else "不匹配"))
    svcs = un.get("services") or []
    if svcs:
        print("  服务商：  " + "  ".join(s.get("name") for s in svcs))
        print("  状态：    " + "  ".join(s.get("status") or "—" for s in svcs))
        print("  地区：    " + "  ".join(s.get("region") or "—" for s in svcs))
        print("  方式：    " + "  ".join(s.get("method") or "—" for s in svcs))
        if any(s.get("source") == "手动" for s in svcs):
            print("  来源：    " + "  ".join((s.get("source") if s.get("source") == "手动" else "—") for s in svcs))

    print()
    print("%s六、邮局连通性及黑名单检测%s" % (c.bold, c.reset))
    mail = report.get("mail") or {}
    print("  本地25端口出站： %s" % (mail.get("local25") or "—"))
    print("  远端25端口：     %s" % (mail.get("remote25") or "—"))
    bl = mail.get("dnsbl") or {}
    print("  IP地址黑名单数据库： 有效 %s  正常 %s  已标记 %s  黑名单 %s" % (
        bl.get("total_valid", 0), bl.get("clean", 0), bl.get("marked", 0), bl.get("listed", 0)))
    if bl.get("failed"):
        print("                   （查询失败或解析器拒绝 %s 家，未计入有效）" % bl["failed"])
    if bl.get("note"):
        print("                   %s" % bl["note"])
    mn = report.get("manual_notes") or {}
    if mn:
        bits = []
        if mn.get("updated"):
            bits.append("记录于 %s（America/New_York）" % mn["updated"])
        if mn.get("observed"):
            bits.append("观测 %s" % mn["observed"])
        print("  手动记录：%s" % ("；".join(bits) if bits else "已应用（手动）"))
    print()


def unlock_pros_cons(unlock):
    if not unlock:
        return [], []
    has_manual = any((s.get("source") == "手动") for s in (unlock.get("services") or []))
    if unlock.get("exit_match") is False and not has_manual:
        return [], []
    if not unlock.get("tested") and not has_manual:
        return [], []
    pros, cons = [], []
    for s in unlock.get("services") or []:
        name, st = s.get("name"), s.get("status")
        # 出口不匹配时，只用手动记录
        if unlock.get("exit_match") is False and s.get("source") != "手动":
            continue
        tag = "（手动）" if s.get("source") == "手动" else ""
        if st in ("屏蔽", "禁会员", "中国", "仅自制"):
            cons.append("%s %s%s" % (name, st, tag))
        elif st == "解锁" and name in ("Netflix", "Disney+", "YouTube", "ChatGPT", "Claude", "Gemini"):
            rg = s.get("region")
            if rg and rg != "—":
                pros.append("%s 解锁（%s）%s" % (name, rg, tag))
            else:
                pros.append("%s 解锁%s" % (name, tag))
    return pros, cons


def format_compare_section_tables(rows):
    def ip_of(r):
        return r.get("_display_ip") or r.get("_ip") or r.get("ip") or "—"

    def sec(r):
        return r.get("sections") or r.get("report") or {}

    t_lines, md_lines = [], []

    def add_table(title, hdr, lines):
        t_lines.append(title)
        t_lines.append(hdr)
        t_lines.extend(lines)
        t_lines.append("")
        md_lines.extend(["## " + title, "", hdr, "|" + "---|" * (hdr.count("|") - 1)])
        md_lines.extend(lines)
        md_lines.append("")

    # 1
    lines = []
    hdr = "| IP | ASN | 组织 | 城市 | 使用地 | 注册地 | 时区 | IP类型 | 登记单位 | 分配 | rDNS |"
    for r in rows:
        b = sec(r).get("basic") or {}
        # 兼容旧 JSON（无硬证据字段）
        he = (sec(r).get("hard_evidence") or r.get("hard_evidence") or b.get("hard_evidence") or {})
        if not b.get("reg_org") and he:
            b = dict(b)
            b.update(_format_hard_basic(he))
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            ip_of(r), b.get("asn", "—"), b.get("org", "—"), b.get("city", "—"),
            b.get("usage_country", "—"), b.get("registered_country", "—"),
            b.get("timezone", "—"), b.get("ip_type", "—"),
            b.get("reg_org") or "—", b.get("reg_alloc") or "—", b.get("rdns_line") or "—"))
    add_table("一、基础信息", hdr, lines)
    # Markdown 里再附硬证据摘要
    md_lines.append("硬证据摘要：")
    md_lines.append("")
    for r in rows:
        b = sec(r).get("basic") or {}
        he = (sec(r).get("hard_evidence") or r.get("hard_evidence") or b.get("hard_evidence") or {})
        sm = b.get("hard_summary") or (he.get("summary") if he else "") or "（无硬证据字段，可能是旧结果）"
        md_lines.append("- %s：%s" % (ip_of(r), sm))
    md_lines.append("")

    db_order = []
    for r in rows:
        for x in (sec(r).get("types") or []):
            if x.get("db") not in db_order:
                db_order.append(x.get("db"))
    hdr = "| IP | " + " | ".join(db_order) + " |"
    lines = []
    for r in rows:
        mp = {x.get("db"): (x.get("usage") or "—") for x in (sec(r).get("types") or [])}
        lines.append("| %s | %s |" % (ip_of(r), " | ".join(mp.get(d, "—") for d in db_order)))
    add_table("二、IP类型属性（各库使用类型）", hdr, lines)

    sorder = []
    for r in rows:
        for x in (sec(r).get("scores") or []):
            if x.get("db") not in sorder:
                sorder.append(x.get("db"))
    hdr = "| IP | " + " | ".join(sorder) + " |"
    lines = []
    for r in rows:
        mp = {}
        for x in (sec(r).get("scores") or []):
            sc, lv = x.get("score"), x.get("level") or "—"
            mp[x.get("db")] = "—" if sc is None and lv in ("未配置", "—") else ("%s（%s）" % (sc if sc is not None else "—", lv))
        lines.append("| %s | %s |" % (ip_of(r), " | ".join(mp.get(d, "—") for d in sorder)))
    add_table("三、风险评分", hdr, lines)

    hdr = "| IP | 代理 | Tor | VPN | 服务器 | 滥用 | 机器人 |"
    lines = []
    for r in rows:
        fac = [x for x in (sec(r).get("factors") or []) if x.get("status") in ("ok", "manual")]
        def cnt(k):
            return sum(1 for x in fac if str(x.get(k) or "").replace("（手动）", "") == "是")
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            ip_of(r), cnt("proxy"), cnt("tor"), cnt("vpn"), cnt("server"), cnt("abuser"), cnt("robot")))
    add_table("四、风险因子（是=阳性库数）", hdr, lines)
    md_lines.append("各库明细：")
    md_lines.append("")
    for r in rows:
        md_lines.append("### %s 风险因子明细" % ip_of(r))
        md_lines.append("")
        md_lines.append("| 库 | 地区 | 代理 | Tor | VPN | 服务器 | 滥用 | 机器人 |")
        md_lines.append("|---|---|---|---|---|---|---|---|")
        for x in (sec(r).get("factors") or []):
            md_lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                x.get("db"), x.get("region") or "—", x.get("proxy") or "—",
                x.get("tor") or "—", x.get("vpn") or "—", x.get("server") or "—",
                x.get("abuser") or "—", x.get("robot") or "—"))
        md_lines.append("")

    svc_names = list(UNLOCK_SERVICES)
    hdr = "| IP | " + " | ".join(svc_names) + " |"
    lines = []
    for r in rows:
        un = sec(r).get("unlock") or {}
        mp = {s.get("name"): s for s in (un.get("services") or [])}
        cells = []
        for n in svc_names:
            s = mp.get(n) or {}
            st = s.get("status") or "未测"
            rg = s.get("region")
            cells.append("未测" if st == "未测" else ("%s %s" % (st, rg) if rg and rg != "—" else st))
        lines.append("| %s | %s |" % (ip_of(r), " | ".join(cells)))
    add_table("五、流媒体及AI解锁", hdr, lines)

    hdr = "| IP | 本地25 | 远端25 | 有效 | 正常 | 已标记 | 黑名单 |"
    lines = []
    for r in rows:
        m = sec(r).get("mail") or {}
        bl = m.get("dnsbl") or {}
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            ip_of(r), m.get("local25") or "—", m.get("remote25") or "—",
            bl.get("total_valid", "—"), bl.get("clean", "—"), bl.get("marked", "—"), bl.get("listed", "—")))
    add_table("六、邮局连通性及黑名单", hdr, lines)
    return "\n".join(t_lines), "\n".join(md_lines)

def parse_note_unlock(spec):
    """Parse --note-unlock 'chatgpt=ok,reddit=blocked,netflix=dns'. Returns list of service dicts."""
    if not spec or not str(spec).strip():
        return []
    items = []
    for raw in str(spec).split(","):
        raw = raw.strip()
        if not raw:
            continue
        if "=" not in raw and ":" not in raw:
            continue
        if "=" in raw:
            k, _, v = raw.partition("=")
        else:
            k, _, v = raw.partition(":")
        key = k.strip().lower().replace(" ", "")
        val = v.strip()
        name = NOTE_UNLOCK_ALIASES.get(key)
        if not name:
            # allow exact report names
            for n in UNLOCK_SERVICES:
                if n.lower().replace("+", "") == key.replace("+", ""):
                    name = n
                    break
        if not name or not val:
            continue
        region = "—"
        method = "手动"
        raw_v = val.strip()
        mreg = re.search(r"\[([A-Za-z]{2})\]", raw_v)
        if mreg:
            region = mreg.group(1).upper()
            raw_v = (raw_v[:mreg.start()] + " " + raw_v[mreg.end():]).strip()
        else:
            mreg = re.search(r"[:/]([A-Za-z]{2})$", raw_v)
            if mreg:
                region = mreg.group(1).upper()
                raw_v = raw_v[:mreg.start()].strip()
        # 方式：原生 / DNS 可写在状态前后
        if re.search(r"(?i)\bDNS\b|DNS", raw_v) and "原生" not in raw_v:
            if re.search(r"(?i)dns", raw_v):
                method = "DNS"
                raw_v = re.sub(r"(?i)DNS", "", raw_v).strip(" /+，,")
        if "原生" in raw_v or re.search(r"(?i)\bnative\b", raw_v):
            method = "原生"
            raw_v = re.sub(r"(?i)原生|native", "", raw_v).strip(" /+，,")
        val_l = re.sub(r"\s+", "", raw_v).lower()
        if not val_l and method in ("DNS", "原生"):
            status = "解锁"
        elif val_l in ("原生", "native"):
            status, method = "解锁", "原生"
        elif val_l in ("dns",):
            status, method = "解锁", "DNS"
        else:
            status = NOTE_STATUS_MAP.get(val_l) or NOTE_STATUS_MAP.get(raw_v.strip())
            if not status:
                m = re.match(r"^(解锁|屏蔽|仅自制|仅APP|仅网页|失败|未测|未知)(?:[（(/]+(原生|DNS|dns|手动)?", raw_v.strip())
                if m:
                    status = m.group(1)
                    if m.group(2):
                        method = "DNS" if m.group(2).lower() == "dns" else ("原生" if m.group(2) in ("原生", "native") else method)
                else:
                    continue
        items.append({
            "name": name, "status": status, "region": region, "method": method,
            "source": "手动",
        })
    # last mention wins
    out = {}
    for it in items:
        out[it["name"]] = it
    return [out[n] for n in UNLOCK_SERVICES if n in out]


def merge_manual_unlock(unlock, manual_items):
    """Fill/override services with user-observed results (source=手动)."""
    unlock = unlock or empty_unlock()
    services = list(unlock.get("services") or [])
    by = {s.get("name"): dict(s) for s in services}
    for n in UNLOCK_SERVICES:
        if n not in by:
            by[n] = {"name": n, "status": "未测", "region": "—", "method": "—"}
    for it in manual_items or []:
        name = it.get("name")
        if not name:
            continue
        cur = by.get(name) or {"name": name, "status": "未测", "region": "—", "method": "—"}
        cur["status"] = it.get("status") or cur.get("status")
        if it.get("region") and it.get("region") != "—":
            cur["region"] = it["region"]
        cur["method"] = it.get("method") or "手动"
        cur["source"] = "手动"
        by[name] = cur
    unlock = dict(unlock)
    unlock["services"] = [by[n] for n in UNLOCK_SERVICES]
    if manual_items:
        unlock["has_manual"] = True
        if not unlock.get("tested"):
            # 仅手动记录时，不要把整段标成「未测」
            reason = unlock.get("reason") or ""
            extra = "部分结果来自手动记录（--note-unlock）"
            if "未测（需 --proxy" in reason or not unlock.get("tested"):
                unlock["reason"] = extra
    return unlock



def redact_secrets(text):
    """日志/错误里绝不带出密钥。"""
    if text is None:
        return text
    s = str(text)
    s = re.sub(r"(ipqualityscore\.com/api/json/ip/)[^/\s\"']+", r"\1***", s, flags=re.I)
    s = re.sub(r"(api[_-]?key=)[^&\s\"']+", r"\1***", s, flags=re.I)
    s = re.sub(r"(Authorization:\s*Bearer\s+)\S+", r"\1***", s, flags=re.I)
    return s


def inspect_ipqs(data, http=None):
    """判定 IPQS 响应是否可用。额度不足不算数据、不导致失败。"""
    if not data or not isinstance(data, dict):
        if http and str(http) not in ("", "200", "0"):
            return {"ok": False, "status": "fail", "reason": "http %s" % http}
        return {"ok": False, "status": "no_data", "reason": "无数据"}
    msg = data.get("message") or data.get("error") or data.get("success_message") or ""
    msg_s = redact_secrets(msg)
    low = msg_s.lower() if isinstance(msg_s, str) else ""
    success = data.get("success")
    credit_hit = any(k in low for k in (
        "insufficient credit", "insufficient credits", "no credits", "out of credit",
        "credit limit", "not enough credit", "quota", "额度不足", "余额不足", "没有额度",
        "0 credits", "zero credits",
    )) or ("credit" in low and any(w in low for w in ("insufficient", "exceed", "empty", "lack", "no ")))
    if credit_hit or (success in (False, "false", 0, "0") and "credit" in low):
        return {"ok": False, "status": "no_credits", "reason": "不可用（额度不足）"}
    if success in (False, "false", 0, "0"):
        return {"ok": False, "status": "error", "reason": "不可用"}
    if data.get("fraud_score") is None and data.get("proxy") is None and data.get("vpn") is None:
        if success in (True, "true", 1, "1"):
            return {"ok": False, "status": "no_data", "reason": "无数据"}
        return {"ok": False, "status": "no_data", "reason": "无数据"}
    return {"ok": True, "status": "ok", "reason": None}


def _note_bool(v):
    if v is None or v == "":
        return None
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "是", "真", "t", "on"):
        return True
    if s in ("0", "false", "no", "n", "否", "假", "f", "off"):
        return False
    return None


def _note_num(v):
    if v is None or v == "":
        return None
    s = str(v).strip().rstrip("%％")
    try:
        if "." in s:
            return float(s)
        return int(s)
    except (TypeError, ValueError):
        return None


# 库名别名 → 规范名
_DB_ALIASES = {
    "ipqs": "ipqs", "ipquality": "ipqs", "ipqualityscore": "ipqs", "ip-quality": "ipqs",
    "ip2location": "ip2location", "ip2": "ip2location", "iplocation": "ip2location",
    "ip2loc": "ip2location",
    "ipapi": "ipapi", "ipapi.is": "ipapi", "ipapi_is": "ipapi",
    "ipinfo": "ipinfo", "ipinfo.io": "ipinfo",
    "ipregistry": "ipregistry",
    "abuseipdb": "abuseipdb", "abuse": "abuseipdb",
    "db-ip": "dbip", "dbip": "dbip", "db_ip": "dbip",
    "scamalytics": "scamalytics", "scam": "scamalytics",
    "dnsbl": "dnsbl", "blacklist": "dnsbl", "黑名单": "dnsbl",
    "iplogs": "iplogs",
    "mail": "mail",
    "local25": "local25", "remote25": "remote25",
}

_FIELD_ALIASES = {
    "type": "type", "usage": "type", "usage_type": "type", "ip_type": "type", "种类": "type",
    "company": "company", "company_type": "company", "org_type": "company",
    "server": "server", "is_server": "server",
    "proxy": "proxy", "is_proxy": "proxy",
    "vpn": "vpn", "is_vpn": "vpn",
    "tor": "tor", "is_tor": "tor",
    "risk": "risk", "score": "score", "fraud": "score", "fraud_score": "score",
    "listed": "listed", "黑名单": "listed",
    "marked": "marked", "已标记": "marked", "pbl": "marked",
    "valid": "valid", "有效": "valid", "total": "valid",
    "normal": "normal", "clean": "normal", "正常": "normal",
    "abuser": "abuser", "robot": "robot",
    "level": "level",
    "observed": "observed", "date": "observed",
}


def parse_note_db(spec):
    """解析 --note-db 'ipqs=75,ipqs.proxy=1,...'。空或非法项忽略。"""
    out = {}
    if not spec:
        return out
    # 允许换行或分号
    raw = str(spec).replace(";", ",").replace("\n", ",")
    for part in raw.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip().lower()
        val = val.strip()
        if not key:
            continue
        if key in ("observed", "date", "noted_at"):
            out.setdefault("_meta", {})["observed"] = val
            continue
        if "." in key:
            db, field = key.split(".", 1)
        else:
            db, field = key, None
        db = _DB_ALIASES.get(db, db)
        # 无字段：按库默认
        if field is None:
            if db in ("local25", "remote25"):
                out.setdefault("mail", {})[db] = val
                continue
            if db == "mail":
                continue
            if db == "dnsbl":
                field = "listed"
            elif db in ("ipqs", "abuseipdb", "scamalytics"):
                field = "score"
            elif db in ("ipapi",):
                # 裸 ipapi=2.20 当风险分；ipapi=business 当类型
                if _note_num(val) is not None:
                    field = "risk"
                else:
                    field = "type"
            elif db == "dbip":
                field = "level"
            else:
                field = "type"
        field = _FIELD_ALIASES.get(field, field)
        bucket = out.setdefault(db, {})
        if field in ("proxy", "vpn", "tor", "server", "abuser", "robot"):
            b = _note_bool(val)
            if b is not None:
                bucket[field] = b
        elif field in ("score", "listed", "marked", "valid", "normal"):
            n = _note_num(val)
            if n is not None:
                bucket[field] = n
        elif field == "risk":
            n = _note_num(val)
            bucket["risk"] = n if n is not None else val
            bucket["risk_raw"] = val
        else:
            bucket[field] = val
    return out


def notes_path(audit_root, ip):
    return os.path.join(audit_root, ip, "notes.json")


def load_notes(audit_root, ip):
    path = notes_path(audit_root, ip)
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def merge_notes(saved, db_new, unlock_new, clear=False):
    """合并持久化手动记录。新键覆盖同名字段；未给出的键保留。clear 先清空再写入本次。"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    base = {} if clear or not saved else dict(saved)
    db = {} if clear else dict(base.get("db") or {})
    if db_new:
        for k, v in db_new.items():
            if k == "_meta":
                continue
            if isinstance(v, dict) and isinstance(db.get(k), dict):
                merged = dict(db[k])
                merged.update(v)
                db[k] = merged
            else:
                db[k] = v
        meta = (db_new or {}).get("_meta") or {}
        if meta.get("observed"):
            db.setdefault("_meta", {})["observed"] = meta["observed"]
    unlock = [] if clear else list(base.get("unlock") or [])
    if unlock_new:
        by_name = {}
        for it in unlock:
            n = (it or {}).get("name")
            if n:
                by_name[n] = dict(it)
        for it in unlock_new:
            n = (it or {}).get("name")
            if n:
                by_name[n] = dict(it)
                by_name[n]["source"] = "手动"
        unlock = [by_name[k] for k in by_name]
    out = {
        "db": db,
        "unlock": unlock,
        "updated": now,
        "source": "手动",
    }
    if (db.get("_meta") or {}).get("observed"):
        out["observed"] = db["_meta"]["observed"]
    elif base.get("observed") and not clear:
        out["observed"] = base["observed"]
    return out


def save_notes(audit_root, ip, notes):
    if not notes:
        return None
    db = notes.get("db") or {}
    unlock = notes.get("unlock") or []
    # 空记录不写
    has_db = any(k != "_meta" for k in db)
    if not has_db and not unlock:
        return None
    d = os.path.join(audit_root, ip)
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
    except TypeError:
        # py3.2 无 exist_ok? 3.2 is old; box has 3.x with exist_ok. fallback:
        try:
            os.makedirs(d, mode=0o700)
        except OSError:
            pass
    path = notes_path(audit_root, ip)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(notes, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def clear_notes_file(audit_root, ip):
    path = notes_path(audit_root, ip)
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            return False
        return True
    return False


def type_vote_of_label(label):
    zh = classify_type(label) if label not in (None, "") else None
    if zh in ("机房", "CDN"):
        return "host", zh
    if zh in ("家宽", "手机"):
        return "res", zh
    return None, zh


_DB_VOTE_TITLE = {
    "ip2location": "IP2Location（手动）",
    "ipinfo": "IPinfo（手动）",
    "ipregistry": "ipregistry（手动）",
    "ipapi": "ipapi（手动）",
    "abuseipdb": "AbuseIPDB（手动）",
    "ipqs": "IPQS（手动）",
    "dbip": "DB-IP（手动）",
    "scamalytics": "Scamalytics（手动）",
    "iplogs": "IPLogs（手动）",
}


def manual_type_votes(db):
    """从手动库产出类型投票。公司类型不单独投票；server=是且无类型时记一票机房。"""
    votes = []
    if not db:
        return votes
    for key, rec in db.items():
        if key in ("_meta", "dnsbl", "mail", "local25", "remote25"):
            continue
        if not isinstance(rec, dict):
            continue
        title = _DB_VOTE_TITLE.get(key, key + "（手动）")
        typ = rec.get("type")
        vote, zh = type_vote_of_label(typ) if typ not in (None, "") else (None, None)
        if vote is None and rec.get("server") is True:
            vote, zh = "host", "机房"
        if vote:
            votes.append((title, vote, "使用类型 %s" % (zh or typ)))
    return votes


def manual_flag_voters(db):
    """手动代理/VPN/Tor 标志。IPQS 等进入高权重源（标题含 ipqs）。"""
    out = []
    if not db:
        return out
    for key, rec in db.items():
        if not isinstance(rec, dict):
            continue
        flags = []
        for name in ("proxy", "vpn", "tor"):
            if rec.get(name) is True:
                flags.append(name)
        if flags:
            # 标题要让 _flag_kind 识别出高权重源
            title = {"ipqs": "IPQS", "ipquality": "IPQS", "scamalytics": "Scamalytics",
                     "ipinfo": "IPinfo", "ipregistry": "ipregistry", "ipdata": "ipdata",
                     "iplogs": "IPLogs", "ip2location": "IP2Location"}.get(key, key)
            out.append((title, flags))
    return out


def ipqs_score_from(db, extras=None, key_status=None):
    """优先用可用的实时 IPQS；否则用手动分数。额度不足的实时响应不用。"""
    insp = None
    if extras and extras.get("ipqs"):
        insp = inspect_ipqs(extras["ipqs"].get("data"), extras["ipqs"].get("http"))
        if insp.get("ok"):
            d = extras["ipqs"]["data"]
            try:
                return int(float(d.get("fraud_score"))), "live"
            except (TypeError, ValueError):
                pass
    rec = (db or {}).get("ipqs") or {}
    if rec.get("score") is not None:
        try:
            return int(float(rec["score"])), "manual"
        except (TypeError, ValueError):
            pass
    return None, (insp.get("status") if insp else None)


def ipapi_risk_level(score):
    try:
        n = float(score)
    except (TypeError, ValueError):
        s = str(score or "")
        if "高" in s:
            return "高风险"
        if "较高" in s or "中" in s:
            return "较高风险" if "较高" in s else "中风险"
        if "低" in s:
            return "低风险"
        return s or None
    # 百分数：0.12 低，2.20 较高
    if n < 1:
        return "低风险"
    if n < 2:
        return "中风险"
    if n < 5:
        return "较高风险"
    return "高风险"


def format_risk_display(val):
    if val is None or val == "":
        return None
    try:
        n = float(val)
        if abs(n - int(n)) < 1e-9:
            return str(int(n))
        # 保留原百分感
        s = ("%g" % n)
        return s
    except (TypeError, ValueError):
        return str(val)


def _tag_manual(text, tagged=True):
    if text in (None, "", "—"):
        return text
    s = str(text)
    if tagged and "（手动）" not in s:
        return s + "（手动）"
    return s


def apply_manual_types(rows, db):
    """把手动类型填进二、表格。未配置/失败的格子用手动值 +（手动）。"""
    if not db:
        return rows
    name_of = {
        "ipinfo": "IPinfo",
        "ipregistry": "ipregistry",
        "ipapi": "ipapi",
        "ip2location": "IP2Location",
        "abuseipdb": "AbuseIPDB",
        "ipqs": "IPQS",
        "dbip": "DB-IP",
        "scamalytics": "Scamalytics",
        "iplogs": "IPLogs",
    }
    by = {r.get("db"): r for r in rows}
    for key, rec in db.items():
        if key not in name_of or not isinstance(rec, dict):
            continue
        dbn = name_of[key]
        typ = rec.get("type")
        company = rec.get("company")
        if typ in (None, "") and company in (None, ""):
            continue
        zh_t = classify_type(typ) if typ not in (None, "") else None
        zh_c = classify_type(company) if company not in (None, "") else None
        r = by.get(dbn)
        if r is None:
            r = _row_type(dbn, _tag_manual(zh_t) if zh_t else "—",
                          _tag_manual(zh_c) if zh_c else "—",
                          "manual", "手动记录")
            rows.append(r)
            by[dbn] = r
            continue
        # 覆盖空/未配置/失败；实时有效数据保留，缺的字段补手动
        fillable = r.get("status") in ("no_key", "fail", "no_data", "no_credits", "error", "no_field", "limited_free") \
            or r.get("usage") in (None, "", "—", "未配置")
        if zh_t and (fillable or r.get("usage") in (None, "", "—", "未配置")):
            r["usage"] = _tag_manual(zh_t)
            r["status"] = "manual" if fillable else r.get("status")
            r["note"] = (r.get("note") or "")
            if "手动" not in (r.get("note") or ""):
                r["note"] = ((r["note"] + "；") if r["note"] else "") + "手动记录"
        elif zh_t and "（手动）" not in str(r.get("usage") or "") and fillable:
            r["usage"] = _tag_manual(zh_t)
        if zh_c and (r.get("company") in (None, "", "—", "未配置") or fillable):
            r["company"] = _tag_manual(zh_c)
    return rows


def apply_manual_scores(rows, db, extras=None):
    if not db:
        return rows
    by = {r.get("db"): r for r in rows}

    def upsert(dbn, score, level, note="手动记录"):
        r = by.get(dbn)
        cell_s = _tag_manual(score if score not in (None, "") else "—")
        cell_l = _tag_manual(level) if level else "—"
        if r is None:
            rows.append({"db": dbn, "score": cell_s, "level": cell_l, "status": "manual", "note": note})
            by[dbn] = rows[-1]
            return
        fillable = r.get("status") in ("no_key", "fail", "no_data", "no_credits", "error") \
            or r.get("score") in (None, "", "—")
        if fillable:
            if score not in (None, ""):
                r["score"] = cell_s
            if level:
                r["level"] = cell_l
            r["status"] = "manual"
            if "手动" not in (r.get("note") or ""):
                r["note"] = ((r.get("note") + "；") if r.get("note") else "") + note

    rec = db.get("ipqs") or {}
    if rec.get("score") is not None:
        upsert("IPQS", rec["score"], ipqs_level(rec["score"]))
    rec = db.get("ip2location") or {}
    if rec.get("risk") is not None:
        upsert("IP2Location", format_risk_display(rec["risk"]), ip2_level(rec["risk"]))
    rec = db.get("ipapi") or {}
    if rec.get("risk") is not None:
        raw = rec.get("risk_raw") or format_risk_display(rec["risk"])
        # 展示带 %（若还没有）
        disp = str(raw)
        if "%" not in disp and _note_num(raw) is not None:
            disp = str(raw).rstrip("%") + "%"
        upsert("ipapi", disp, ipapi_risk_level(rec["risk"]))
    rec = db.get("abuseipdb") or {}
    if rec.get("score") is not None:
        upsert("AbuseIPDB", rec["score"], abuse_level(rec["score"]))
    rec = db.get("scamalytics") or {}
    if rec.get("score") is not None:
        upsert("Scamalytics", rec["score"], scam_level(rec["score"]))
    rec = db.get("dbip") or {}
    if rec.get("level") not in (None, "") or rec.get("score") is not None:
        lv = rec.get("level") or dbip_level(rec.get("score"))
        upsert("DB-IP", rec.get("score") if rec.get("score") is not None else lv, dbip_level(lv) or lv)
    return rows


def apply_manual_factors(rows, db):
    if not db:
        return rows
    name_of = {
        "ipinfo": "IPinfo", "ipregistry": "ipregistry", "ipapi": "ipapi",
        "ip2location": "IP2Location", "abuseipdb": "AbuseIPDB", "ipqs": "IPQS",
        "scamalytics": "Scamalytics", "dbip": "DB-IP", "iplogs": "IPLogs",
    }
    by = {r.get("db"): r for r in rows}

    def zh_cell(v):
        if v is True:
            return "是"
        if v is False:
            return "否"
        return None

    for key, rec in db.items():
        if key not in name_of or not isinstance(rec, dict):
            continue
        dbn = name_of[key]
        r = by.get(dbn)
        fields = {
            "proxy": zh_cell(rec["proxy"]) if "proxy" in rec else None,
            "tor": zh_cell(rec["tor"]) if "tor" in rec else None,
            "vpn": zh_cell(rec["vpn"]) if "vpn" in rec else None,
            "server": zh_cell(rec["server"]) if "server" in rec else None,
            "abuser": zh_cell(rec["abuser"]) if "abuser" in rec else None,
            "robot": zh_cell(rec["robot"]) if "robot" in rec else None,
        }
        if not any(v is not None for v in fields.values()):
            continue
        if r is None:
            r = _factor(dbn,
                        proxy=_tag_manual(fields["proxy"] or "—"),
                        tor=_tag_manual(fields["tor"] or "—"),
                        vpn=_tag_manual(fields["vpn"] or "—"),
                        server=_tag_manual(fields["server"] or "—"),
                        abuser=_tag_manual(fields["abuser"]) if fields["abuser"] else None,
                        robot=_tag_manual(fields["robot"]) if fields["robot"] else None,
                        independent=True, note="手动记录", status="manual")
            rows.append(r)
            by[dbn] = r
            continue
        # 手动字段覆盖免费层（例如 IP2Location 免费层只有 is_proxy，截图来自完整库）
        for f in ("proxy", "tor", "vpn", "server", "abuser", "robot"):
            if fields[f] is None:
                continue
            r[f] = _tag_manual(fields[f])
        if "手动" not in (r.get("note") or ""):
            r["note"] = ((r.get("note") + "；") if r.get("note") else "") + "手动记录"
        if r.get("status") in ("no_key", "fail", "no_data", "no_credits", "error", None):
            r["status"] = "manual"
    return rows


def notes_has_content(notes):
    if not notes or not isinstance(notes, dict):
        return False
    db = notes.get("db") or {}
    if any(k != "_meta" for k in db):
        return True
    if notes.get("unlock"):
        return True
    return False


# 手动黑名单有效库过少时视为覆盖不全，不当信号（例如截图只查到 1 家）
DNSBL_COVERAGE_MIN = 10


def dnsbl_coverage_incomplete(rec):
    if not rec:
        return False
    if rec.get("valid") is None:
        return False
    try:
        n = int(rec.get("valid"))
    except (TypeError, ValueError):
        return False
    return 0 < n < DNSBL_COVERAGE_MIN


def apply_manual_mail(mail, db):
    if not db or not mail:
        return mail
    rec_mail = db.get("mail") or {}
    # 也接受顶层 local25/remote25
    for k in ("local25", "remote25"):
        val = rec_mail.get(k)
        if val is None and isinstance(db.get(k), dict):
            val = None
        if val is None and k in db and not isinstance(db.get(k), dict):
            val = db[k]
        if val not in (None, ""):
            # 未实测时用手动
            cur = mail.get(k)
            if cur in (None, "", "—") or ("未测" in str(cur)) or ("仅 VPS" in str(cur)):
                mail[k] = _tag_manual(val)
    rec = db.get("dnsbl") or {}
    if rec:
        bl = dict(mail.get("dnsbl") or {})
        bl["doh"] = {
            "total_valid": bl.get("total_valid"),
            "clean": bl.get("clean"),
            "marked": bl.get("marked"),
            "listed": bl.get("listed"),
            "hits": bl.get("hits"),
            "failed": bl.get("failed"),
        }
        if rec.get("valid") is not None:
            bl["total_valid"] = int(rec["valid"]) if not isinstance(rec["valid"], int) else rec["valid"]
        if rec.get("normal") is not None:
            bl["clean"] = rec["normal"]
        if rec.get("marked") is not None:
            bl["marked"] = rec["marked"]
        if rec.get("listed") is not None:
            bl["listed"] = rec["listed"]
        incomplete = dnsbl_coverage_incomplete(rec)
        bl["source"] = "manual"
        bl["coverage_incomplete"] = bool(incomplete)
        if incomplete:
            # 覆盖不全：展示截图数字，但不当作黑名单信号；计分仍看本次 DoH / coffee
            note = "有效库仅 %s 家，覆盖不全，不当作黑名单信号" % rec.get("valid")
            if bl.get("doh") and bl["doh"].get("total_valid"):
                note += "（本次 DoH 抽样 有效 %s / 正常 %s / 已标记 %s / 黑名单 %s）" % (
                    bl["doh"].get("total_valid"), bl["doh"].get("clean"),
                    bl["doh"].get("marked"), bl["doh"].get("listed"))
            # 计分用的 listed 不采用覆盖不全的截图（listed 即使为 0 也不要盖掉 DoH 命中）
            if bl.get("doh"):
                if bl["doh"].get("listed"):
                    bl["listed"] = bl["doh"].get("listed")
            bl["note"] = note + "（手动）"
        else:
            note = "黑名单计数来自手动记录"
            if bl.get("doh") and bl["doh"].get("total_valid"):
                note += "（本次 DoH 抽样 有效 %s / 正常 %s / 已标记 %s / 黑名单 %s）" % (
                    bl["doh"].get("total_valid"), bl["doh"].get("clean"),
                    bl["doh"].get("marked"), bl["doh"].get("listed"))
            bl["note"] = note + "（手动）"
        mail["dnsbl"] = bl
    return mail


def manual_dnsbl_listed(db):
    rec = (db or {}).get("dnsbl") or {}
    if dnsbl_coverage_incomplete(rec):
        return 0
    try:
        n = int(rec.get("listed"))
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def ipqs_risk_bits(score, source=""):
    """综合分用的 IPQS 扣分与原因。≥75 可疑（复核），≥85 严重。"""
    if score is None:
        return 0, None, None  # pts, review_msg, reject_msg
    try:
        n = int(float(score))
    except (TypeError, ValueError):
        return 0, None, None
    tag = "（手动）" if source == "manual" else ""
    if n >= 85:
        return -20, "IPQS %d 高风险%s" % (n, tag), "IPQS ≥ 85，高风险%s" % tag
    if n >= 75:
        return -10, "IPQS %d 可疑%s" % (n, tag), None
    return 0, None, None


def _svc(unlock, name):
    for s in (unlock or {}).get("services") or []:
        if s.get("name") == name:
            return s
    return {}


def _ai_status(unlock, name):
    st = (_svc(unlock, name) or {}).get("status") or "未测"
    if st in ("未测", "失败", "—", "", None):
        return None
    if str(st).startswith("未知"):
        return None
    return st


def has_ai_unlock_data(unlock):
    return any(_ai_status(unlock, n) for n in ("ChatGPT", "Claude", "Gemini"))


def ip2_risk_from(notes_db, extras=None):
    rec = (notes_db or {}).get("ip2location") or {}
    if rec.get("risk") is not None:
        try:
            return float(rec["risk"]), "manual"
        except (TypeError, ValueError):
            pass
    d = ((extras or {}).get("ip2location") or {}).get("data") or {}
    if d.get("fraud_score") is not None:
        try:
            return float(d["fraud_score"]), "live"
        except (TypeError, ValueError):
            pass
    return None, None


def ip2_has_anon(notes_db, flag_voters=None):
    rec = (notes_db or {}).get("ip2location") or {}
    if rec.get("proxy") or rec.get("vpn") or rec.get("tor"):
        return True
    for item in flag_voters or []:
        title = item[0] if not isinstance(item, dict) else (item.get("source") or item.get("title"))
        flags = item[1] if not isinstance(item, dict) else (item.get("flags") or [])
        if "ip2location" in (title or "").lower() and any(f in ("proxy", "vpn", "tor") for f in (flags or [])):
            return True
    return False


def ip2_risk_bits(risk, has_anon, source=""):
    """IP2Location ≥75 且 proxy/VPN：与 IPQS 同类，高权重并建议放弃。"""
    if risk is None:
        return 0, None, None
    try:
        n = float(risk)
    except (TypeError, ValueError):
        return 0, None, None
    tag = "（手动）" if source == "manual" else ""
    disp = ("%g" % n)
    if n >= 75 and has_anon:
        return -20, "IP2Location %s 高风险且 proxy/VPN%s" % (disp, tag), (
            "IP2Location risk %s 且标记 proxy/VPN，建议放弃%s" % (disp, tag)
        )
    if n >= 75:
        return -10, "IP2Location %s 高风险%s" % (disp, tag), None
    return 0, None, None


def _flag_kind(title, weight=None, ip2_risk=None):
    if weight == "high":
        return "high"
    if weight == "low":
        return "low"
    t = (title or "").lower()
    for h in HIGH_FLAG_SOURCES:
        if h in t:
            return "high"
    # IP2Location 风险 ≥75 且已作为代理/VPN 旗（由调用方保证）→ 高权重，与 IPQS 同类
    if "ip2location" in t or t == "ip2":
        try:
            if ip2_risk is not None and float(ip2_risk) >= 75:
                return "high"
        except (TypeError, ValueError):
            pass
    return "low"


def flag_entry_weight(title, flags=None, notes_db=None, ip2_risk=None):
    risk = ip2_risk
    if risk is None and notes_db is not None:
        risk, _src = ip2_risk_from(notes_db)
    return _flag_kind(title, ip2_risk=risk)


def _flags_from_row(flags, ip2_risk=None):
    """Return (high_n, low_n, labels). flags is JSON list of {source, flags, weight?}."""
    high = low = 0
    labels = []
    for item in flags or []:
        if isinstance(item, dict):
            title = item.get("source") or item.get("title") or ""
            fl = item.get("flags") or []
            weight = item.get("weight")
            item_risk = item.get("risk") if item.get("risk") is not None else ip2_risk
        else:
            title, fl, weight, item_risk = str(item), ["flag"], None, ip2_risk
        if not fl:
            continue
        kind = _flag_kind(title, weight=weight, ip2_risk=item_risk)
        if kind == "high":
            high += 1
        else:
            low += 1
        labels.append("%s(%s)" % (title, "/".join(fl) if isinstance(fl, (list, tuple)) else fl))
    return high, low, labels


def score_ai_use(row):
    """AI 适用分 0-100. row 可以是 lite JSON，或现场拼好的同名字段。"""
    flags = row.get("flags") or []
    ip2_risk = row.get("ip2location_risk")
    if ip2_risk is None:
        rec = ((row.get("manual_notes") or {}).get("db") or {}).get("ip2location") or {}
        if rec.get("risk") is not None:
            ip2_risk = rec.get("risk")
        else:
            for s in ((row.get("sections") or {}).get("scores") or []):
                if s.get("db") == "IP2Location" and s.get("score") not in (None, "", "—"):
                    raw = str(s.get("score")).replace("（手动）", "").strip()
                    try:
                        ip2_risk = float(raw)
                    except (TypeError, ValueError):
                        pass
                    break
    high_n, low_n, flag_labs = _flags_from_row(flags, ip2_risk=ip2_risk)
    scam = row.get("scamalytics_score")
    try:
        scam = int(scam) if scam is not None else None
    except (TypeError, ValueError):
        scam = None
    tv = row.get("type_votes") or {}
    try:
        res_n = float(tv.get("residential") or 0)
    except (TypeError, ValueError):
        res_n = 0.0
    try:
        host_n = float(tv.get("hosting") or 0)
    except (TypeError, ValueError):
        host_n = 0.0
    host_majority = host_n > res_n and host_n >= 2

    dnsbl_hits = row.get("dnsbl_hits") or []
    # 也可能在 sections.mail.dnsbl
    mail = ((row.get("sections") or {}).get("mail") or {})
    bl = mail.get("dnsbl") or {}
    listed = bl.get("listed") or 0
    abuse = row.get("abuseipdb") or {}
    try:
        ascore = int(abuse["score"]) if abuse.get("score") is not None else None
    except (TypeError, ValueError, KeyError):
        ascore = None
    try:
        reps = int(abuse.get("reports") or 0)
    except (TypeError, ValueError):
        reps = 0
    # breakdown fallback for older JSON
    if ascore is None:
        for b in row.get("breakdown") or []:
            if b.get("item") == "AbuseIPDB" and "score" in str(b.get("detail") or ""):
                m = re.search(r"score\s*[:=]?\s*(\d+)", str(b.get("detail")))
                if m:
                    try:
                        ascore = int(m.group(1))
                    except ValueError:
                        pass

    he = row.get("hard_evidence") or ((row.get("sections") or {}).get("hard_evidence") or {})
    he_flags = he.get("flags") or {}
    rdns = he.get("rdns") or {}
    no_ptr = (rdns.get("style") == "none") or (not rdns.get("ptr") and not rdns.get("error"))
    # 旧 JSON 无硬证据时不要乱扣
    if not he:
        no_ptr = False

    bonus = bool(row.get("operator_bonus"))
    consistent_isp = bool(he_flags.get("consistent_isp"))
    business = (row.get("operator_kind") == "business")

    unlock = row.get("unlock") or ((row.get("sections") or {}).get("unlock") or {})

    # ----- 代理/VPN/Tor 30：高权重源（Scamalytics/IPQS 等）扣得更重 -----
    # 每个高权重源 -20，低权重（IPLogs 等）-10
    p_flags = 30 - 20 * high_n - 10 * low_n
    if p_flags < 0:
        p_flags = 0
    if high_n == 0 and low_n == 0:
        d_flags = "无"
    else:
        d_flags = "、".join(flag_labs) + ("（高权重源）" if high_n else "（低权重源）")

    # ----- 滥用/黑名单 25 -----
    dirty_bl = bool(dnsbl_hits) or (isinstance(listed, int) and listed > 0)
    dirty_abuse = (ascore is not None and ascore >= 25) or reps >= 5
    severe_abuse = (ascore is not None and ascore >= 75)
    if dirty_bl or severe_abuse:
        p_ab, d_ab = 0, "黑名单命中或 AbuseIPDB 放弃线"
        if dnsbl_hits:
            d_ab = "DNSBL 命中: " + "; ".join(str(x) for x in dnsbl_hits[:4])
        elif severe_abuse:
            d_ab = "AbuseIPDB score %s" % ascore
    elif dirty_abuse:
        p_ab, d_ab = 8, "AbuseIPDB score=%s reports=%s" % (ascore, reps)
    else:
        p_ab, d_ab = 25, "未列" if not dnsbl_hits else "仅 PBL"

    # ----- Scamalytics 15（中等）-----
    if scam is None:
        p_sc, d_sc = 8, "未取到分数"
    elif scam <= 10:
        p_sc, d_sc = 15, "%d（低）" % scam
    elif scam <= 25:
        # 11 → 9，25 → 5
        p_sc = int(round(9 - (scam - 11) * (9 - 5) / 14.0))
        if p_sc < 4:
            p_sc = 4
        d_sc = "%d（11–25）" % scam
    else:
        p_sc, d_sc = 0, "%d（>25）" % scam

    # ----- 机房票 15：3:2 只轻扣，机房多数仍重扣 -----
    if host_n == 0:
        p_ho, d_ho = 15, "机房 0 票"
    elif host_majority:
        p_ho, d_ho = 0, "机房多数 %s:%s" % (fmt_vote(res_n), fmt_vote(host_n))
    elif host_n >= 2:
        p_ho, d_ho = 12, "家宽 %s : 机房 %s（轻扣）" % (fmt_vote(res_n), fmt_vote(host_n))
    else:
        p_ho, d_ho = 13, "家宽 %s : 机房 %s" % (fmt_vote(res_n), fmt_vote(host_n))

    # ----- 登记/rDNS 5：很轻 -----
    p_reg = 5
    bits = []
    if he_flags.get("mismatch") or he_flags.get("reassigned"):
        p_reg -= 2
        bits.append("登记与 ASN 不一致")
    if no_ptr:
        p_reg -= 2
        bits.append("无 PTR")
    if he_flags.get("leased") or he_flags.get("hosting_org"):
        p_reg -= 1
        bits.append("租用/机房登记")
    if p_reg < 0:
        p_reg = 0
    d_reg = "；".join(bits) if bits else "无特别风险"

    # ----- 主流运营商 10：小加分 -----
    if bonus or (consistent_isp and not business):
        p_isp, d_isp = 10, (row.get("operator") or (he.get("registry") or {}).get("org") or "ISP")
    else:
        p_isp, d_isp = 0, "无"

    base = p_flags + p_ab + p_sc + p_ho + p_reg + p_isp

    # ----- 解锁加减（有 ChatGPT/Claude/Gemini 结果时才计入，且权重大）-----
    adj = 0
    adj_bits = []
    if has_ai_unlock_data(unlock):
        def _one(name, plus, minus, mid=0):
            st = _ai_status(unlock, name)
            svc = _svc(unlock, name)
            src = "手动" if (svc.get("source") == "手动") else None
            tag = "（手动%s）" % (("，" + svc.get("method")) if svc.get("method") in ("原生", "DNS") else "") if src else ""
            if svc.get("source") == "手动" and not tag.endswith("）"):
                tag = "（手动）"
            if st == "解锁":
                return plus, "%s 解锁%s" % (name, tag)
            if st in ("仅APP", "仅网页"):
                return mid or max(1, plus // 3), "%s %s%s" % (name, st, tag)
            if st == "屏蔽":
                return minus, "%s 屏蔽%s" % (name, tag)
            return 0, None

        a, b = _one("ChatGPT", 20, -25, mid=6)
        adj += a
        if b:
            adj_bits.append(b)
        a, b = _one("Claude", 8, -10, mid=0)
        adj += a
        if b:
            adj_bits.append(b)
        a, b = _one("Gemini", 5, -6, mid=0)
        adj += a
        if b:
            adj_bits.append(b)
        d_unl = "；".join(adj_bits) if adj_bits else "—"
    else:
        d_unl = "未测 ChatGPT/Claude/Gemini，不加解锁分"

    # IPQS 分数（≥75 可疑，≥85 严重）；额度不足的响应不会出现在这里
    ipqs_score = row.get("ipqs_score")
    if ipqs_score is None:
        for s in ((row.get("sections") or {}).get("scores") or []):
            if s.get("db") == "IPQS" and s.get("score") not in (None, "", "—"):
                raw = str(s.get("score")).replace("（手动）", "").strip()
                try:
                    ipqs_score = float(raw)
                    break
                except (TypeError, ValueError):
                    pass
    try:
        ipqs_score = int(float(ipqs_score)) if ipqs_score is not None else None
    except (TypeError, ValueError):
        ipqs_score = None
    if ipqs_score is not None:
        if ipqs_score >= 85:
            adj -= 15
            adj_bits.append("IPQS %d 高风险" % ipqs_score)
        elif ipqs_score >= 75:
            adj -= 8
            adj_bits.append("IPQS %d 可疑" % ipqs_score)
        else:
            adj_bits.append("IPQS %d" % ipqs_score)
        if adj_bits:
            d_unl = "；".join(adj_bits)

    total = base + adj
    if total < 0:
        total = 0
    if total > 100:
        total = 100

    # 建议
    cg = _ai_status(unlock, "ChatGPT")
    reasons = []
    if any("ChatGPT 解锁" in x for x in adj_bits):
        reasons.append([x for x in adj_bits if x.startswith("ChatGPT")][0])
    elif cg == "屏蔽":
        reasons.append("ChatGPT 屏蔽")
    for x in adj_bits:
        if x.startswith("Claude") or x.startswith("Gemini"):
            reasons.append(x)
    if high_n == 0 and low_n == 0:
        reasons.append("无代理/VPN/Tor 标志")
    else:
        reasons.append("代理/VPN 标记: " + d_flags)
    reasons.append("黑名单" + ("命中" if dirty_bl else "未列"))
    if scam is not None:
        reasons.append("Scamalytics %d" % scam)
    if ipqs_score is not None:
        if ipqs_score >= 75:
            reasons.append("IPQS %d %s" % (ipqs_score, "高风险" if ipqs_score >= 85 else "可疑"))
        else:
            reasons.append("IPQS %d" % ipqs_score)
    if host_majority:
        reasons.append("机房多数 %s:%s" % (fmt_vote(res_n), fmt_vote(host_n)))
    elif host_n >= 2:
        reasons.append("机房票 %s:%s" % (fmt_vote(res_n), fmt_vote(host_n)))
    if bits:
        reasons.extend(bits)

    if cg == "屏蔽" or dirty_bl or severe_abuse or high_n + low_n >= 2 or (high_n >= 1 and low_n >= 1) or (ipqs_score is not None and ipqs_score >= 85):
        verdict = "不建议"
    elif host_majority and (cg != "解锁"):
        verdict = "不建议"
    elif total >= 75 and high_n == 0 and not dirty_bl and not host_majority and cg != "屏蔽":
        # 有 ChatGPT 解锁，或完全干净且未测解锁：可用；仅有低权重标记时改观察
        if cg == "解锁" or (cg is None and low_n == 0):
            verdict = "可用"
        else:
            verdict = "观察"
    elif total >= 50:
        verdict = "观察"
    else:
        verdict = "不建议"

    # 有中段风险时，可用降为观察？Fraud 25 + 3:2 仍可「可用」但原因里写明。按上面规则 72.1 为可用。
    breakdown = [
        ("代理/VPN/Tor", p_flags, 30, d_flags),
        ("滥用/黑名单", p_ab, 25, d_ab),
        ("Scamalytics", p_sc, 15, d_sc),
        ("机房票", p_ho, 15, d_ho),
        ("登记/rDNS", p_reg, 5, d_reg),
        ("主流运营商", p_isp, 10, d_isp),
        ("解锁加减", adj, 0, d_unl),
    ]
    summary = "AI 用途: %d / 100  建议：%s" % (total, verdict)
    return {
        "score": total,
        "verdict": verdict,
        "reasons": reasons,
        "breakdown": [
            {"item": n, "points": g, "max": m, "detail": d} for n, g, m, d in breakdown
        ],
        "summary": summary,
        "adjustment": adj,
        "base": base,
        "chatgpt": cg,
    }


def format_ai_block(ai, color=False):
    if not ai:
        return ""
    lines = [ai.get("summary") or ("AI 用途: %s / 100" % ai.get("score"))]
    for row in ai.get("breakdown") or []:
        mx = row.get("max") or 0
        got = row.get("points")
        if row.get("item") == "解锁加减":
            lines.append("  %-16s %+4d  %s" % (row.get("item"), got, row.get("detail") or ""))
        else:
            lines.append("  %-16s %2d/%-2d  %s" % (row.get("item"), got, mx, row.get("detail") or ""))
    if ai.get("reasons"):
        lines.append("  原因: " + "；".join(ai["reasons"]))
    return "\n".join(lines)
