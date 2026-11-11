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

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
)

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
        "dch": "机房", "idc": "机房", "server": "机房", "cloud": "机房",
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


def color_type(text, c):
    if text in ("家宽", "手机"):
        return c.bg_green + " " + text + " " + c.reset
    if text in ("机房", "CDN", "蜘蛛"):
        return c.bg_red + " " + text + " " + c.reset
    if text not in ("—", "未配置", None, ""):
        return c.bg_yellow + " " + text + " " + c.reset
    return text or "—"


def color_bool(text, c):
    if text == "是":
        return c.red + c.bold + "是" + c.reset
    if text == "否":
        return c.green + c.bold + "否" + c.reset
    return text


def color_level(level, c):
    if not level or level in ("—", "未配置"):
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
    return {"low": "低风险", "medium": "中风险", "high": "高风险"}.get(str(text).strip().lower())


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


def _doh_a(name, timeout=6):
    url = "https://dns.google/resolve?name=%s&type=A" % name
    try:
        p = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout), url],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2,
        )
        if p.returncode != 0 or not p.stdout:
            return None, "doh_fail"
        data = json.loads(p.stdout.decode("utf-8", "replace"))
        answers = []
        for a in data.get("Answer") or []:
            if a.get("type") == 1 and a.get("data"):
                answers.append(str(a["data"]).strip())
        if answers:
            return answers, "ok"
        if data.get("Status") == 3:
            return [], "nxdomain"
        return [], "empty"
    except Exception:
        return None, "error"


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


def run_unlock(target_ip, mode, cfg_path=None):
    services_empty = [
        {"name": n, "status": "未测", "region": "—", "method": "—"}
        for n in ("TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "Reddit", "ChatGPT")
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
    checks = [check_tiktok, check_disney, check_netflix, check_youtube, check_amazon, check_reddit, check_chatgpt]
    services = []
    pretty = {
        "tiktok": "TikTok", "disney": "Disney+", "netflix": "Netflix",
        "youtube": "YouTube", "amazon": "AmazonPV", "reddit": "Reddit", "chatgpt": "ChatGPT",
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


def build_types(sources, extras, key_status):
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
    return rows


def build_scores(sources, extras, key_status):
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
    if key_status.get("ipqs"):
        d = (extras.get("ipqs") or {}).get("data") or {}
        sc = d.get("fraud_score")
        rows.append({"db": "IPQS", "score": sc, "level": ipqs_level(sc) or "—", "status": "ok"})
    else:
        rows.append({"db": "IPQS", "score": None, "level": "未配置", "status": "no_key"})
    d = (extras.get("dbip") or {}).get("data") or {}
    if d and d.get("threatLevel"):
        rows.append({"db": "DB-IP", "score": d.get("threatLevel"), "level": dbip_level(d.get("threatLevel")) or "—", "status": "ok"})
    else:
        rows.append({"db": "DB-IP", "score": None, "level": "未配置", "status": "no_key", "note": "免费层无 threatLevel"})
    return rows

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


def build_factors(sources, extras, key_status):
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
    if key_status.get("ipqs"):
        d = (extras.get("ipqs") or {}).get("data") or {}
        rows.append(_factor("IPQS", region=d.get("country_code"), proxy=d.get("proxy"),
            tor=d.get("tor"), vpn=d.get("vpn"), abuser=d.get("recent_abuse"), robot=d.get("bot_status"), independent=True))
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
    return rows


def empty_unlock():
    return {
        "tested": False,
        "reason": "未测（需 --proxy 或在该 IP 的机器上运行）",
        "exit_ip": None, "exit_match": None,
        "services": [{"name": n, "status": "未测", "region": "—", "method": "—"}
                     for n in ("TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "Reddit", "ChatGPT")],
    }


def build_mail(mode, local25, remote25, dnsbl):
    if mode == "bare":
        local_s = "仅 VPS 上可测"
        remote_s = "未测（需 --proxy 或在该 IP 的机器上运行）"
    else:
        local_s = local25 if mode == "local" else "仅 VPS 上可测"
        remote_s = remote25 or "—"
    return {"local25": local_s, "remote25": remote_s, "dnsbl": dnsbl or {}}


def build_report(ctx):
    sources = ctx["sources"]
    extras = ctx.get("extras") or {}
    key_status = ctx.get("key_status") or {}
    meta = ctx.get("meta") or {}
    return {
        "basic": build_basic(sources, extras, meta),
        "types": build_types(sources, extras, key_status),
        "scores": build_scores(sources, extras, key_status),
        "factors": build_factors(sources, extras, key_status),
        "unlock": ctx.get("unlock") or empty_unlock(),
        "mail": build_mail(ctx.get("mode") or "bare", ctx.get("local25"), ctx.get("remote25"), ctx.get("dnsbl")),
    }


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
    print()


def unlock_pros_cons(unlock):
    if not unlock or not unlock.get("tested") or unlock.get("exit_match") is False:
        return [], []
    pros, cons = [], []
    for s in unlock.get("services") or []:
        name, st = s.get("name"), s.get("status")
        if st in ("屏蔽", "禁会员", "中国", "仅自制"):
            cons.append("%s %s" % (name, st))
        elif st == "解锁" and name in ("Netflix", "Disney+", "YouTube", "ChatGPT"):
            rg = s.get("region")
            pros.append("%s 解锁（%s）" % (name, rg) if rg and rg != "—" else "%s 解锁" % name)
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
    hdr = "| IP | ASN | 组织 | 城市 | 使用地 | 注册地 | 时区 | IP类型 |"
    for r in rows:
        b = sec(r).get("basic") or {}
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            ip_of(r), b.get("asn", "—"), b.get("org", "—"), b.get("city", "—"),
            b.get("usage_country", "—"), b.get("registered_country", "—"),
            b.get("timezone", "—"), b.get("ip_type", "—")))
    add_table("一、基础信息", hdr, lines)

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
        fac = [x for x in (sec(r).get("factors") or []) if x.get("status") == "ok"]
        def cnt(k):
            return sum(1 for x in fac if x.get(k) == "是")
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

    svc_names = ["TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "Reddit", "ChatGPT"]
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
