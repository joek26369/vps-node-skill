#!/bin/bash
# ============================================================================
# 质量快照对比：拿同一台机器最近两次 NodeQuality 快照做并排比较
#
# 用法: bash vps-quality-diff.sh <凭据别名|IP> [选项]
#   --all            列出全部快照而不做对比
#   --json           机读输出（供 automation 汇总）
#   --prev <目录>    手工指定基线快照目录
#   --cur  <目录>    手工指定本次快照目录
#
# 退出码: 0=无退化 / 3=存在退化项 / 1=快照不足 / 2=参数错
#
# 快照目录: ~/.vps-node/reports/<IP下划线>/<stamp>/  （vps-quality-report.sh 自动归档）
# 缺 metrics.json 时，会尝试用同目录/同期的日志现场解析补上。
# ============================================================================
set -uo pipefail

ARG="${1:?用法: vps-quality-diff.sh <凭据别名|IP> [--all|--json]}"
shift || true
ALL=0; JSONOUT=0; PREV=""; CUR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --all)  ALL=1; shift ;;
    --json) JSONOUT=1; shift ;;
    --prev) PREV="${2:?--prev 需要目录}"; shift 2 ;;
    --cur)  CUR="${2:?--cur 需要目录}"; shift 2 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREDDIR="$HOME/.vps-node"
REPORTS="$CREDDIR/reports"

# ---- 解析别名 → IP ----
IP=""
CREDS=""
if [ -f "$ARG" ]; then CREDS="$ARG"
elif [ -f "$CREDDIR/$ARG.json" ]; then CREDS="$CREDDIR/$ARG.json"
elif printf '%s' "$ARG" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then IP="$ARG"
else
  for f in "$CREDDIR"/*.json; do
    [ -f "$f" ] || continue
    grep -q "\"ip\": *\"$ARG\"" "$f" && { CREDS="$f"; break; }
  done
fi
if [ -z "$IP" ] && [ -n "$CREDS" ]; then
  IP=$(python3 -c "import json;print(json.load(open('$CREDS')).get('ip',''))" 2>/dev/null)
  SPORT=$(python3 -c "import json;print(json.load(open('$CREDS')).get('ssh_port',''))" 2>/dev/null)
  ALIAS=$(basename "$CREDS" .json)
else
  ALIAS="$ARG"
  SPORT=""
fi
[ -n "$IP" ] || { echo "❌ 找不到该别名对应的 IP: $ARG"; exit 2; }
[ -n "${SPORT:-}" ] || SPORT=22

IPDIR=$(printf '%s' "$IP" | tr '.' '_')
DIR="$REPORTS/$IPDIR"
[ -d "$DIR" ] || { echo "❌ 还没有任何快照: $DIR"; echo "   先跑一次: bash $HERE/vps-quality-report.sh $IP $SPORT"; exit 1; }

# 按时间戳目录排序（目录名即 YYYYMMDD-HHMM）；macOS 自带 bash 3.2 没有 mapfile，用 while read 攒
SNAPS=()
while IFS= read -r line; do
  [ -n "$line" ] && SNAPS+=("$line")
done <<EOF
$(ls -1 "$DIR" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{4}$' | sort)
EOF
CNT=${#SNAPS[@]}

if [ "$ALL" = "1" ]; then
  echo "快照目录: $DIR"
  for s in "${SNAPS[@]}"; do
    m="$DIR/$s/metrics.json"
    if [ -f "$m" ]; then
      info=$(python3 -c "import json;d=json.load(open('$m'));print(d.get('mode','?'), '|', (d.get('ip') or {}).get('asn','?'), '|', len(d.get('net',{}).get('lat',{})), '城市延迟')" 2>/dev/null)
    else
      info="（缺 metrics.json）"
    fi
    echo "  $s  $info"
  done
  exit 0
fi

if [ "$CNT" -lt 2 ] && { [ -z "$PREV" ] || [ -z "$CUR" ]; }; then
  echo "⚠️ 只有 $CNT 个快照，没法对比（需要两次）"
  echo "   目录: $DIR"
  [ "$CNT" = "1" ] && echo "   已有: ${SNAPS[0]}"
  echo "   再跑一次即可: bash $HERE/vps-quality-report.sh $IP $SPORT"
  exit 1
fi

# ---- 确定基线 / 本次 ----
if [ -z "$CUR" ]; then CUR="$DIR/${SNAPS[$((CNT-1))]}"; fi
if [ -z "$PREV" ]; then PREV="$DIR/${SNAPS[$((CNT-2))]}"; fi

# ---- 缺 metrics.json 就从日志补 ----
ensure_metrics(){
  local snap="$1" mj="$1/metrics.json"
  [ -f "$mj" ] && return 0
  local stamp; stamp=$(basename "$snap")
  # 日志可能在 ~/.vps-node/ 下，也可能在快照目录里
  local log=""
  for c in "$snap"/*.log "$CREDDIR"/*quality*"$stamp"*.log; do
    [ -f "$c" ] && { log="$c"; break; }
  done
  [ -n "$log" ] || return 1
  local mode="unknown"
  grep -q '快速硬件 + 全量网络\|f\\ny\\ny\\ny' "$log" 2>/dev/null && mode="full"
  python3 "$HERE/vps-quality-parse.py" "$log" --mode "$mode" -o "$mj" >/dev/null 2>&1 || return 1
  chmod 600 "$mj"
  echo "  （已从日志补出 $(basename "$snap")/metrics.json）" >&2
}

ensure_metrics "$PREV" || { echo "❌ 基线快照缺 metrics.json 且找不到对应日志: $PREV"; exit 1; }
ensure_metrics "$CUR"  || { echo "❌ 本次快照缺 metrics.json 且找不到对应日志: $CUR";  exit 1; }

TITLE="$ALIAS ($IP) 质量对比"
if [ "$JSONOUT" = "1" ]; then
  python3 "$HERE/vps-quality-diff.py" "$PREV/metrics.json" "$CUR/metrics.json" --json --title "$TITLE"
else
  python3 "$HERE/vps-quality-diff.py" "$PREV/metrics.json" "$CUR/metrics.json" --title "$TITLE"
fi
exit $?
