#!/bin/bash
# ============================================================================
# 把多次 ip-check-lite.sh 的结果放在一起比较，看哪条 IP 更值得留。
#
# 用法:
#   bash ip-compare.sh <IP1> <IP2> [IP3 ...]
#   bash ip-compare.sh --all                 # 比较 ~/.vps-node/ipaudits 下所有已测 IP
#   bash ip-compare.sh --rerun <IP1> <IP2>   # 先重跑快查再比较
#   bash ip-compare.sh --mask <IP...>        # 表格里把 IP 打成 a.b.*.*，方便外传
#   bash ip-compare.sh --since 7d --all      # 只纳入该时间窗口内的最新结果
#   bash ip-compare.sh --for ai <IP...>      # 按 AI 适用分排名（默认仍按综合分/家宽真实性）
#
# 除排名表外，还会按六段（基础信息 / 类型 / 评分 / 因子 / 解锁 / 邮局黑名单）汇总。
# Markdown 报告同时给出「综合」和「AI 用途」两套排名。
# 解锁未跑时显示「未测」。终端用紧凑表，Markdown 含因子明细。
#
# 每条 IP 读取 ~/.vps-node/ipaudits/<IP>/ 下最新的 lite-*.json。
# 没有 JSON 的 IP 会提示先跑 ip-check-lite.sh 或加 --rerun。
# 比较报告同时写到 ~/.vps-node/ipaudits/compare-<stamp>.md（600）。
#
# 退出码: 0 完成比较 / 1 有 IP 缺结果或无可比数据 / 2 参数错误
# ============================================================================
set -uo pipefail

usage() {
  printf '用法: ip-compare.sh [--rerun] [--mask] [--all] [--since 7d] [--for general|ai] <IP...>\n' >&2
  printf '比较已保存的裸 IP 快查结果。默认按综合分（家宽真实性）排序；--for ai 按 AI 适用分排序。\n' >&2
}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd) || exit 2
LITE="$SCRIPT_DIR/ip-check-lite.sh"
AUDIT_ROOT="${HOME}/.vps-node/ipaudits"

RERUN=0
MASK=0
ALL=0
SINCE=""
FOR_MODE="general"
IPS=""

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 2
      ;;
    --rerun) RERUN=1 ;;
    --mask)  MASK=1 ;;
    --all)   ALL=1 ;;
    --for)
      shift
      FOR_MODE="${1:-}"
      case "$FOR_MODE" in
        general|ai) ;;
        *)
          printf '错误: --for 只支持 general 或 ai\n' >&2
          exit 2
          ;;
      esac
      ;;
    --for=*)
      FOR_MODE="${1#--for=}"
      case "$FOR_MODE" in
        general|ai) ;;
        *)
          printf '错误: --for 只支持 general 或 ai\n' >&2
          exit 2
          ;;
      esac
      ;;
    --since)
      shift
      if [ $# -lt 1 ]; then
        printf -- '--since 需要一个时间窗口，例如 7d 或 24h\n' >&2
        exit 2
      fi
      SINCE=$1
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf '未知参数: %s\n' "$1" >&2
      usage
      exit 2
      ;;
    *)
      if [ -z "$IPS" ]; then
        IPS=$1
      else
        IPS="$IPS $1"
      fi
      ;;
  esac
  shift
done
while [ $# -gt 0 ]; do
  if [ -z "$IPS" ]; then
    IPS=$1
  else
    IPS="$IPS $1"
  fi
  shift
done

if [ "$ALL" = 1 ]; then
  if [ ! -d "$AUDIT_ROOT" ]; then
    printf '还没有体检记录目录: %s\n先跑: bash %s <IP>\n' "$AUDIT_ROOT" "$LITE" >&2
    exit 1
  fi
  _found=""
  for _d in "$AUDIT_ROOT"/*/; do
    [ -d "$_d" ] || continue
    _base=$(basename "$_d")
    case "$_base" in
      *[!0-9.]*|'') continue ;;
    esac
    if [ -z "$_found" ]; then
      _found=$_base
    else
      _found="$_found $_base"
    fi
  done
  if [ -z "$_found" ]; then
    printf '在 %s 下没有找到任何 IP 目录。\n' "$AUDIT_ROOT" >&2
    exit 1
  fi
  if [ -z "$IPS" ]; then
    IPS=$_found
  else
    IPS="$IPS $_found"
  fi
fi

if [ -z "$IPS" ]; then
  usage
  exit 2
fi

# 去重（保持顺序），bash 3.2 不用关联数组
_uniq=""
for _ip in $IPS; do
  _dup=0
  for _u in $_uniq; do
    if [ "$_u" = "$_ip" ]; then
      _dup=1
      break
    fi
  done
  if [ "$_dup" = 0 ]; then
    if [ -z "$_uniq" ]; then
      _uniq=$_ip
    else
      _uniq="$_uniq $_ip"
    fi
  fi
done
IPS=$_uniq

if [ "$RERUN" = 1 ]; then
  if [ ! -x "$LITE" ] && [ ! -f "$LITE" ]; then
    printf '找不到 ip-check-lite.sh: %s\n' "$LITE" >&2
    exit 2
  fi
  for _ip in $IPS; do
    printf '== 重跑快查: %s ==\n' "$_ip"
    bash "$LITE" "$_ip" || true
    printf '\n'
  done
fi

umask 077
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$AUDIT_ROOT"
MD="$AUDIT_ROOT/compare-${STAMP}.md"
_n=1
while [ -e "$MD" ]; do
  _n=$((_n + 1))
  MD="$AUDIT_ROOT/compare-${STAMP}-${_n}.md"
done
MANIFEST=$(mktemp "${TMPDIR:-/tmp}/ip-compare.XXXXXX")
# shellcheck disable=SC2329
CLEANUP() {
  [ -n "${MANIFEST:-}" ] && rm -f "$MANIFEST"
}
trap CLEANUP EXIT

: > "$MANIFEST"
MISSING=""
for _ip in $IPS; do
  _dir="$AUDIT_ROOT/$_ip"
  _json=""
  if [ -d "$_dir" ]; then
    # 按文件名排序，取最新一份 lite-*.json
    _json=$(find "$_dir" -maxdepth 1 -name 'lite-*.json' -type f -print 2>/dev/null | sort | tail -n 1 || true)
  fi
  if [ -z "$_json" ] || [ ! -f "$_json" ]; then
    printf '没有 %s 的快查 JSON。请先跑: bash %s %s\n或加上 --rerun。\n' "$_ip" "$LITE" "$_ip" >&2
    if [ -z "$MISSING" ]; then
      MISSING=$_ip
    else
      MISSING="$MISSING $_ip"
    fi
    continue
  fi
  printf '%s\t%s\n' "$_ip" "$_json" >> "$MANIFEST"
done

if [ ! -s "$MANIFEST" ]; then
  printf '没有可比较的结果。\n' >&2
  exit 1
fi

export IPCOMPARE_MASK="$MASK"
export IPCOMPARE_SINCE="$SINCE"
export IPCOMPARE_MD="$MD"
export IPCOMPARE_MISSING="$MISSING"
export IPCOMPARE_LIB="$SCRIPT_DIR"
export IPCOMPARE_FOR="$FOR_MODE"
python3 - "$MANIFEST" <<'PY'
import json, os, re, sys
from datetime import datetime, timedelta
_lib = os.environ.get("IPCOMPARE_LIB") or ""
if _lib and _lib not in sys.path:
    sys.path.insert(0, _lib)
import ipcheck_report as ipr

manifest = sys.argv[1]
mask = os.environ.get("IPCOMPARE_MASK") == "1"
since_raw = (os.environ.get("IPCOMPARE_SINCE") or "").strip()
md_path = os.environ.get("IPCOMPARE_MD") or ""
missing = [x for x in (os.environ.get("IPCOMPARE_MISSING") or "").split() if x]
for_mode = (os.environ.get("IPCOMPARE_FOR") or "general").strip().lower()
if for_mode not in ("general", "ai"):
    for_mode = "general"

def parse_since(s):
    if not s:
        return None
    m = re.fullmatch(r"(\d+)\s*([dDhHmM])", s)
    if not m:
        raise ValueError("无法解析 --since %s（例: 7d, 24h）" % s)
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "d":
        return timedelta(days=n)
    if unit == "h":
        return timedelta(hours=n)
    if unit == "m":
        return timedelta(minutes=n)
    return None

try:
    since_td = parse_since(since_raw)
except ValueError as e:
    print(e, file=sys.stderr)
    sys.exit(2)

def parse_ts(s):
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # +0800 without colon is already %z on some pythons; try inserting colon
    m = re.match(r"(.+)([+-]\d{2})(\d{2})$", s)
    if m:
        try:
            return datetime.strptime(m.group(1) + m.group(2) + ":" + m.group(3), "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            return None
    return None

def mask_ip(ip):
    parts = (ip or "").split(".")
    if len(parts) == 4:
        return "%s.%s.*.*" % (parts[0], parts[1])
    return ip

def flags_n(d):
    fs = d.get("flags") or []
    n = 0
    for item in fs:
        if isinstance(item, dict):
            n += len(item.get("flags") or [])
        else:
            n += 1
    return n

def flags_text(d):
    fs = d.get("flags") or []
    if not fs:
        return "无"
    bits = []
    for item in fs:
        if isinstance(item, dict):
            bits.append("/".join(item.get("flags") or []) or "有")
        else:
            bits.append(str(item))
    return "、".join(bits)

def load_row(ip, path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    d["_ip"] = ip
    d["_path"] = path
    d["_ts"] = parse_ts(d.get("timestamp") or "")
    return d

rows = []
errors = []
now = datetime.now().astimezone() if hasattr(datetime, "now") else datetime.now()
try:
    now = datetime.now().astimezone()
except Exception:
    now = datetime.now()

with open(manifest, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        ip, path = line.split("\t", 1)
        try:
            rows.append(load_row(ip, path))
        except (OSError, ValueError, json.JSONDecodeError) as e:
            errors.append("%s 的 JSON 读不出来（%s）: %s" % (ip, path, e))

# --since 过滤
filtered_out = []
if since_td is not None:
    kept = []
    for r in rows:
        ts = r["_ts"]
        if ts is None:
            filtered_out.append((r, "没有时间戳"))
            continue
        ts_aware = ts
        if ts.tzinfo is None:
            try:
                ts_aware = ts.replace(tzinfo=now.tzinfo)
            except Exception:
                ts_aware = ts
        try:
            age = now - ts_aware
        except TypeError:
            age = now.replace(tzinfo=None) - ts.replace(tzinfo=None)
        if age > since_td:
            filtered_out.append((r, "超出 --since %s" % since_raw))
            continue
        kept.append(r)
    rows = kept

if not rows:
    print("没有落在比较范围内的结果。")
    if filtered_out:
        print("被 --since 过滤掉的:")
        for r, why in filtered_out:
            print("  - %s（%s）" % (r["_ip"], why))
    sys.exit(1)

# 补算旧 JSON 里没有的 AI 适用分（不改文件）
for r in rows:
    if r.get("ai_score") is None:
        try:
            ai = ipr.score_ai_use(r)
            r["ai_score"] = ai.get("score")
            r["ai_verdict"] = ai.get("verdict")
            r["ai_reasons"] = ai.get("reasons") or []
            r["ai_breakdown"] = ai.get("breakdown") or []
            r["ai_summary"] = ai.get("summary")
        except Exception:
            r.setdefault("ai_score", None)

# 排序：留(pass) 最好，然后待复核，最后换；同分再比分数、加分、更少标记、更新的测试
verdict_rank = {"pass": 0, "review": 1, "reject": 2}

def sort_key(r):
    v = verdict_rank.get(r.get("verdict") or "", 9)
    score = r.get("score")
    if not isinstance(score, (int, float)):
        score = -1
    bonus = 1 if r.get("operator_bonus") else 0
    fl = flags_n(r)
    ts = r.get("_ts")
    # newer is better: use timestamp or min
    ts_ord = ts or datetime(1970, 1, 1)
    if getattr(ts_ord, "tzinfo", None) is not None:
        try:
            ts_naive = ts_ord.replace(tzinfo=None)
        except Exception:
            ts_naive = datetime(1970, 1, 1)
    else:
        ts_naive = ts_ord
    return (v, -score, -bonus, fl, -ts_naive.timestamp())

def _ts_naive(r):
    ts = r.get("_ts") or datetime(1970, 1, 1)
    if getattr(ts, "tzinfo", None) is not None:
        try:
            return ts.replace(tzinfo=None)
        except Exception:
            return datetime(1970, 1, 1)
    return ts

def chatgpt_status(r):
    un = r.get("unlock") or (r.get("sections") or {}).get("unlock") or {}
    for s in un.get("services") or []:
        if s.get("name") == "ChatGPT":
            return s.get("status") or "未测"
    return "未测"

def chatgpt_rank(r):
    st = chatgpt_status(r)
    return {"解锁": 0, "仅APP": 1, "仅网页": 1, "未测": 2, "失败": 2, "屏蔽": 3}.get(st, 2)

def sort_key_ai(r):
    score = r.get("ai_score")
    if not isinstance(score, (int, float)):
        score = -1
    scam = r.get("scamalytics_score")
    try:
        scam_n = int(scam) if scam is not None else 999
    except (TypeError, ValueError):
        scam_n = 999
    return (-score, flags_n(r), chatgpt_rank(r), scam_n, -_ts_naive(r).timestamp())

rows_general = list(rows)
rows_general.sort(key=sort_key)
rows_ai = list(rows)
rows_ai.sort(key=sort_key_ai)
rows = rows_ai if for_mode == "ai" else rows_general

def display_ip(ip):
    return mask_ip(ip) if mask else ip

def verdict_cell(r):
    return r.get("verdict_zh") or {"pass": "留", "review": "待复核", "reject": "换"}.get(r.get("verdict"), "?")

def op_cell(r):
    op = r.get("operator") or "—"
    if r.get("operator_kind") == "business":
        return "%s（商业线）" % op
    if r.get("operator_bonus") and r.get("operator_mobile"):
        return "%s（移动）" % op
    if r.get("operator_bonus"):
        return op
    if r.get("operator_kind") == "bonus":
        return op
    return op if op != "—" else "—"

def type_cell(r):
    tv = r.get("type_votes") or {}
    res = tv.get("residential", "?")
    host = tv.get("hosting", "?")
    extra = ""
    if tv.get("bonus_applied"):
        extra = "+1"
    return "%s%s:%s" % (res, extra, host)

def scam_cell(r):
    s = r.get("scamalytics_score")
    return "—" if s is None else str(s)

def native_cell(r):
    return {"native": "原生", "broadcast": "广播", "unknown": "未知"}.get(r.get("native") or "", r.get("native") or "—")

def bl_cell(r):
    hits = r.get("dnsbl_hits") or []
    pbl = r.get("dnsbl_pbl") or []
    if hits:
        return "命中"
    if pbl:
        return "仅 PBL"
    return "未列"

def time_cell(r):
    ts = r.get("timestamp") or "—"
    # 显示本地可读短格式
    parsed = r.get("_ts")
    if parsed:
        try:
            return parsed.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return ts[:16].replace("T", " ")
    return ts[:16].replace("T", " ") if ts else "—"

def is_stale(r, days=7):
    ts = r.get("_ts")
    if not ts:
        return False
    try:
        if ts.tzinfo is None:
            age = datetime.now() - ts
        else:
            age = datetime.now().astimezone() - ts
        return age > timedelta(days=days)
    except Exception:
        return False

# 打印表格
headers = ["排名", "IP", "综合分", "结论", "运营商", "类型票(家宽:机房)", "代理标记", "Scamalytics", "原生", "黑名单", "测试时间"]
headers_ai = ["排名", "IP", "AI适用分", "AI建议", "综合分", "结论", "ChatGPT", "代理标记", "Scamalytics", "类型票(家宽:机房)", "测试时间"]

def row_vals(i, r):
    return [
        str(i),
        display_ip(r["_ip"]),
        str(r.get("score") if r.get("score") is not None else "—"),
        verdict_cell(r),
        op_cell(r),
        type_cell(r),
        flags_text(r),
        scam_cell(r),
        native_cell(r),
        bl_cell(r),
        time_cell(r),
    ]

def row_vals_ai(i, r):
    return [
        str(i),
        display_ip(r["_ip"]),
        str(r.get("ai_score") if r.get("ai_score") is not None else "—"),
        r.get("ai_verdict") or "—",
        str(r.get("score") if r.get("score") is not None else "—"),
        verdict_cell(r),
        chatgpt_status(r),
        flags_text(r),
        scam_cell(r),
        type_cell(r),
        time_cell(r),
    ]

print("======== IP 比较（%s）========" % ("AI 用途" if for_mode == "ai" else "综合 / 家宽真实性"))

# markdown table + plain text
def fmt_table(hdr, rows_vals):
    lines = []
    lines.append("| " + " | ".join(hdr) + " |")
    lines.append("|" + "|".join(["---"] * len(hdr)) + "|")
    for vals in rows_vals:
        lines.append("| " + " | ".join(vals) + " |")
    return "\n".join(lines)

table_general = fmt_table(headers, [row_vals(i, r) for i, r in enumerate(rows_general, 1)])
table_ai = fmt_table(headers_ai, [row_vals_ai(i, r) for i, r in enumerate(rows_ai, 1)])
table_md = table_ai if for_mode == "ai" else table_general
print(table_md)
print()
# 另一套排名的紧凑对照
other_title = "综合排名（家宽真实性）" if for_mode == "ai" else "AI 用途排名"
other_tbl = table_general if for_mode == "ai" else table_ai
print("======== %s ========" % other_title)
print(other_tbl)
print()

# 六段汇总（终端紧凑表）
for r in rows:
    r["_display_ip"] = display_ip(r["_ip"])
sec_term, sec_md = ipr.format_compare_section_tables(rows)
print("======== 六段汇总 ========")
print(sec_term)

# 警告
warnings = []
for r in rows:
    if is_stale(r, 7):
        warnings.append("%s 的结果超过 7 天，建议 --rerun" % display_ip(r["_ip"]))
for r, why in filtered_out:
    warnings.append("%s 未纳入本次比较（%s）" % (display_ip(r["_ip"]), why))
for ip in missing:
    warnings.append("%s 没有 JSON，已跳过。请先跑 ip-check-lite.sh 或加 --rerun" % (mask_ip(ip) if mask else ip))
for e in errors:
    warnings.append(e)

if warnings:
    print("注意:")
    for w in warnings:
        print("  - " + w)
    print()

# 推荐段落（综合排名用 rows_general；AI 用 rows_ai）
top_g = rows_general[0]
top_a = rows_ai[0]
top = top_a if for_mode == "ai" else top_g
top_ip = display_ip(top["_ip"])
top_v = verdict_cell(top)
keepers = [r for r in rows_general if r.get("verdict") == "pass"]
reviews = [r for r in rows_general if r.get("verdict") == "review"]
rejects = [r for r in rows_general if r.get("verdict") == "reject"]

para_g = []
para_g.append("更值得留的是 %s（综合分 %s，结论：%s）。" % (
    display_ip(top_g["_ip"]), top_g.get("score") if top_g.get("score") is not None else "—", verdict_cell(top_g)
))
sug = top_g.get("suggestion") or ""
if sug:
    para_g.append("它的单条建议是「%s」。" % sug)

def only_source_failure(r):
    # 旧 JSON 可能把「机房票 ≥ 2 / 代理标记」误标成 source_failure，比较时再挡一层
    if r.get("review_reason") != "source_failure":
        return False
    tv = r.get("type_votes") or {}
    try:
        host = int(tv.get("hosting") or 0)
    except (TypeError, ValueError):
        host = 0
    if host >= 2:
        return False
    if r.get("flags"):
        return False
    return True

if top_g.get("verdict") == "review" and only_source_failure(top_g):
    failed = "、".join(top_g.get("failed_sources") or []) or "检测源"
    para_g.append("但第一名仍是「待复核」，原因是仅检测源失败（%s），不是这份 IP 本身更差。源恢复后建议 --rerun，再据此做决定。" % failed)
elif top_g.get("verdict") == "review":
    para_g.append("第一名仍是「待复核」，先看清风险再决定是否留下。")
elif top_g.get("verdict") == "reject":
    para_g.append("这次比较里没有任何明确可留的地址，第一名也建议换。")

if rejects:
    para_g.append("建议换掉: " + "、".join("%s（%s）" % (display_ip(r["_ip"]), r.get("suggestion") or "放弃") for r in rejects) + "。")
if reviews:
    only_fail = [r for r in reviews if only_source_failure(r)]
    real = [r for r in reviews if not only_source_failure(r)]
    if only_fail and only_fail != reviews:
        para_g.append("因源失败而待复核（类型与标志本身不差）: " + "、".join(display_ip(r["_ip"]) for r in only_fail) + "。")
    if real:
        para_g.append("因实际信号待复核: " + "、".join(display_ip(r["_ip"]) for r in real) + "。")

if len(rows_general) >= 2:
    second = rows_general[1]
    if (top_g.get("score") or 0) == (second.get("score") or 0) and top_g.get("verdict") == second.get("verdict"):
        why = "并列时优先结论更好者，再比综合分、主流运营商加分、更少的代理标记、更新的测试。"
        if top_g.get("operator_bonus") and not second.get("operator_bonus"):
            why = "与 %s 分数相同，因有主流家宽运营商加分而排在前面。" % display_ip(second["_ip"])
        para_g.append(why)

para_a = []
para_a.append("更适合 AI 用途的是 %s（AI 适用分 %s，建议：%s）。" % (
    display_ip(top_a["_ip"]),
    top_a.get("ai_score") if top_a.get("ai_score") is not None else "—",
    top_a.get("ai_verdict") or "—",
))
if top_a.get("ai_reasons"):
    para_a.append("原因：" + "；".join(top_a["ai_reasons"][:6]) + "。")
if len(rows_ai) >= 2:
    second_a = rows_ai[1]
    para_a.append("其后是 %s（%s，%s）。" % (
        display_ip(second_a["_ip"]),
        second_a.get("ai_score") if second_a.get("ai_score") is not None else "—",
        second_a.get("ai_verdict") or "—",
    ))

para = para_a if for_mode == "ai" else para_g
print("建议:")
print("  " + "".join(para))
print()


# 写 markdown
md_lines = []
md_lines.append("# IP 快查比较")
md_lines.append("")
md_lines.append("比较时间: %s" % now.strftime("%Y-%m-%d %H:%M:%S"))
md_lines.append("")
md_lines.append("终端本次主排名：%s。" % ("AI 用途" if for_mode == "ai" else "综合（家宽真实性）"))
md_lines.append("")
md_lines.append("## 两种排名对照")
md_lines.append("")
# 一行对照：名次从左到右
def rank_line(lst, score_key, extra_key=None):
    cells = ["第 %d：%s（%s）" % (
        i, display_ip(r["_ip"]),
        r.get(score_key) if r.get(score_key) is not None else "—",
    ) + (("，" + str(r.get(extra_key))) if extra_key and r.get(extra_key) else "")
        for i, r in enumerate(lst, 1)]
    return "、".join(cells)

md_lines.append("- 综合（家宽真实性）：" + rank_line(rows_general, "score", "verdict_zh"))
md_lines.append("- AI 用途：" + rank_line(rows_ai, "ai_score", "ai_verdict"))
md_lines.append("")
md_lines.append("## 综合排名（家宽真实性）")
md_lines.append("")
md_lines.append(table_general)
md_lines.append("")
md_lines.append("".join(para_g))
md_lines.append("")
md_lines.append("## AI 用途排名")
md_lines.append("")
md_lines.append(table_ai)
md_lines.append("")
md_lines.append("".join(para_a))
md_lines.append("")
md_lines.append(sec_md)
md_lines.append("")
if warnings:
    md_lines.append("## 注意")
    md_lines.append("")
    for w in warnings:
        md_lines.append("- " + w)
    md_lines.append("")
md_lines.append("## 建议")
md_lines.append("")
md_lines.append("".join(para))
md_lines.append("")
md_lines.append("## 各 IP 单条建议")
md_lines.append("")
for i, r in enumerate(rows, 1):
    md_lines.append("### %d. %s — %s，综合分 %s" % (
        i, display_ip(r["_ip"]), verdict_cell(r), r.get("score") if r.get("score") is not None else "—"
    ))
    md_lines.append("")
    if r.get("suggestion"):
        md_lines.append("- 建议: %s" % r["suggestion"])
    op = op_cell(r)
    md_lines.append("- 运营商: %s；类型票 %s；代理 %s；Scamalytics %s；%s；黑名单 %s" % (
        op, type_cell(r), flags_text(r), scam_cell(r), native_cell(r), bl_cell(r)
    ))
    he = (r.get("hard_evidence") or (r.get("sections") or {}).get("hard_evidence")
          or ((r.get("sections") or {}).get("basic") or {}).get("hard_evidence") or {})
    if he.get("summary"):
        md_lines.append("- %s" % he["summary"])
    if r.get("ai_summary"):
        md_lines.append("- %s" % r["ai_summary"])
        if r.get("ai_reasons"):
            md_lines.append("- AI 原因: " + "；".join(r["ai_reasons"]))
    elif he:
        md_lines.append("- 硬证据: 登记单位 %s；分配 %s；rDNS %s" % (
            (he.get("registry") or {}).get("org") or "—",
            (he.get("registry") or {}).get("allocation") or "—",
            (he.get("rdns") or {}).get("style_zh") or "—",
        ))
    if r.get("failed_sources"):
        md_lines.append("- 失败源: " + "、".join(r["failed_sources"]))
    md_lines.append("")

text = "\n".join(md_lines) + "\n"
if md_path:
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(md_path, 0o600)
    except OSError:
        pass
    print("报告: %s" % md_path)

sys.exit(1 if missing or errors else 0)
PY
RC=$?
exit "$RC"
