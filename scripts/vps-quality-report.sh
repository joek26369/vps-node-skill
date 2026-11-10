#!/bin/bash
# ============================================================================
# NodeQuality 深度质量报告（在 Mac 上运行，驱动远端 VPS 跑）
# 用法: bash vps-quality-report.sh <VPS_IP> [SSH端口] [--full|--lowdata]
#   默认  : 硬件快速(f) + IP质量(y) + 网络质量(y) + 回程路由(y)   约 10-20 分钟
#   --full: 硬件深度(v) + 其余全开                              约 20-35 分钟
#   --lowdata: 网络质量低流量(l)，适合计费流量紧张的机器          约 8-15 分钟
#
# 说明: 上游 https://github.com/LloydAsp/NodeQuality
#       ＊ 它把结果 zip 上传到 api.nodequality.com，返回一个公开链接
#       ＊ 跑完会自行 rm -rf 本地结果，唯一留存就是那个链接
#       ＊ 需要 root、chroot、约 2GB 空闲磁盘；LXC/OpenVZ 可能失败
# ============================================================================
set -uo pipefail
IP="${1:?用法: vps-quality-report.sh <VPS_IP> [SSH端口] [--full|--lowdata]}"
PORT="${2:-22}"
MODE="${3:-}"
KEY="${SSH_KEY:-}"
if [ -z "$KEY" ]; then
  for k in "$HOME/.ssh/id_ed25519_vps" "$HOME"/.ssh/id_ed25519_* \
           "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
    [ -f "$k" ] || continue
    case "$k" in *.pub) continue ;; esac
    KEY="$k"; break
  done
fi
CREDDIR="$HOME/.vps-node"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP=$(date +%Y%m%d-%H%M)

DRY=0
case "$MODE" in
  --dry-run) DRY=1;  ANSWERS='f\ny\ny\ny\n'; DESC="仅环境自检（不跑测试）"; TMO=120 ;;
  --full)    ANSWERS='v\ny\ny\ny\n'; DESC="深度硬件 + 全量";       TMO=2100 ;;
  --lowdata) ANSWERS='f\ny\nl\ny\n'; DESC="快速硬件 + 低流量网络";  TMO=1200 ;;
  *)         ANSWERS='f\ny\ny\ny\n'; DESC="快速硬件 + 全量网络";    TMO=1500 ;;
esac
# 供结构化指标落盘用（日志里反推不出模式，必须由这里显式给）
case "$MODE" in
  --full)    MNAME=full ;;
  --lowdata) MNAME=lowdata ;;
  *)         MNAME=full ;;
esac

echo "=============== NodeQuality 质量报告: $IP ==============="
echo "  模式: $DESC"
echo "  ⚠️ 结果会自动上传到 nodequality.com 生成公开链接"
echo "  ⚠️ 网络质量测试会消耗流量（低流量模式约 300MB-1GB，全量可能 2-3GB）"
echo ""

SSHOPT=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=15 -o BatchMode=yes -o LogLevel=ERROR -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=10 -p "$PORT")

echo "  连接检查..."
if ! ssh "${SSHOPT[@]}" "root@$IP" 'echo SSH_OK' 2>/dev/null | grep -q SSH_OK; then
  echo "  ❌ SSH 不通（密钥 $KEY / 端口 ${PORT}）"; exit 1
fi
FREE=$(ssh "${SSHOPT[@]}" "root@$IP" "df -Pm / | awk 'NR==2{print \$4}'" 2>/dev/null)
ARCH=$(ssh "${SSHOPT[@]}" "root@$IP" "uname -m; command -v chroot >/dev/null && echo HAS_CHROOT" 2>/dev/null | tr '\n' ' ')
echo "  架构: $ARCH  可用磁盘: ${FREE:-?} MB"
if [ -n "${FREE:-}" ] && [ "$FREE" -lt 1800 ] 2>/dev/null; then
  echo "  ⚠️ 可用磁盘不足 1.8GB，BenchOS 解压可能失败，建议先清理"
fi
echo ""
if [ "$DRY" = "1" ]; then
  echo "  --dry-run: 检查远端能否下载入口脚本并解析..."
  ssh "${SSHOPT[@]}" "root@$IP" \
    'curl -sL --max-time 60 https://run.NodeQuality.com -o /tmp/nq.sh && echo "size=$(wc -c </tmp/nq.sh) bytes" && bash -n /tmp/nq.sh && echo "PARSE_OK" && grep -q "api.nodequality.com" /tmp/nq.sh && echo "UPLOAD_ENDPOINT_PRESENT"' 2>&1 | sed 's/^/    /'
  echo ""
  echo "  环境满足即可去掉 --dry-run 正式跑。"
  echo "=============== 自检结束 ==============="
  exit 0
fi

echo "  开始测试（预计 $((TMO/60-3)) 分钟左右，中途不要断网）..."
echo "  ---- 以下为远端实时输出 ----"

LOG="$CREDDIR/$(echo "$IP" | tr '.' '_')-quality-$STAMP.log"
mkdir -p "$CREDDIR"; chmod 700 "$CREDDIR"

# 远端：下载入口脚本 → 喂答案非交互执行（ask_question 用 read，默认 y）
REMOTE_CMD="curl -sL --max-time 60 https://run.NodeQuality.com -o /tmp/nq.sh && printf '$ANSWERS' | bash /tmp/nq.sh 2>&1"

perl -e 'alarm shift; exec @ARGV' "$TMO" \
  ssh "${SSHOPT[@]}" "root@$IP" "$REMOTE_CMD" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]:-0}

echo ""
echo "  ---- 远端输出结束 ----"
if [ "$RC" = "142" ] || [ "$RC" = "124" ]; then
  echo "  ⚠️ 超时中断（${TMO}s）。上游脚本会在收到 TERM 时清理 chroot，但请确认:"
  echo "     ssh -p $PORT root@$IP 'mount | grep nodequality'   # 有输出则手工 umount -R 并删除目录"
fi

# 提取上传后的公开链接
URL=$(grep -oE 'https?://nodequality\.com/r/[A-Za-z0-9]+' "$LOG" | tail -1 || true)
echo ""
if [ -n "$URL" ]; then
  echo "  ✅ 报告链接: $URL"
else
  echo "  ⚠️ 未捕获到报告链接（可能上传失败或输出被截断）"
  echo "     上游很可能仍上传成功，可到 https://nodequality.com 查最近记录"
fi
chmod 600 "$LOG"

# 归档：xykt 三份分报告 SVG 存本地。上游没有公开保留策略、也没有删除接口，
# 想隔一段时间做前后对比，只能靠自己这份副本。
IPDIR=$(echo "$IP" | tr '.' '_')
ARCH="$CREDDIR/reports/$IPDIR/$STAMP"
FOUND=$(grep -oE 'https://Report\.Check\.Place/(hardware|ip|net)/[A-Za-z0-9]+\.svg' "$LOG" 2>/dev/null | sort -u || true)
if [ -n "$FOUND" ]; then
  mkdir -p "$ARCH"; chmod 700 "$CREDDIR/reports" 2>/dev/null
  echo "$FOUND" | while read -r u; do
    n=$(basename "$u")
    if curl -sL --max-time 40 "$u" -o "$ARCH/$n" && [ -s "$ARCH/$n" ]; then
      echo "  已归档: $n"
    else
      echo "  ⚠️ 归档失败: $u"
    fi
  done
  chmod 600 "$ARCH"/*.svg 2>/dev/null
  echo "  本地归档: $ARCH"
  # 结构化指标：供 vps-quality-diff.sh 做前后对比
  if python3 "$HERE/vps-quality-parse.py" "$LOG" --mode "$MNAME" -o "$ARCH/metrics.json" 2>/dev/null; then
    chmod 600 "$ARCH/metrics.json"
    echo "  指标快照: $ARCH/metrics.json"
  else
    echo "  ⚠️ 指标解析失败（不影响报告本身，只影响后续对比）"
  fi
else
  echo "  ⚠️ 日志里没找到分报告链接，未归档"
fi

echo "  完整日志: $LOG"
echo "=============== 完成 ==============="
echo ""
echo "  对比两次测试: 直接比 $CREDDIR/reports/$IPDIR/ 下不同日期的同名 SVG"
echo ""
echo "与 skill 内置检查的分工:"
echo "  vps-external-ip-check.sh  → IP 纯净度 9 项（快，1-2 分钟，已自动跑）"
echo "  vps-verify.sh             → 节点功能验收（快，30 秒）"
echo "  vps-quality-report.sh     → 硬件 + 流媒体解锁 + 全网测速 + 回程路由（慢，这一份）"
