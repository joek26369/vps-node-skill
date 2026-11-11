#!/bin/bash
# ============================================================================
# 线路体检（在 Mac 上运行）：去程（本机 → VPS）+ 回程（VPS → 国内）
# 用法: bash vps-route-check.sh <VPS_IP> [SSH端口] [国内目标IP]
# 默认: SSH 端口取 22，国内目标 114.114.114.114
# 环境: SSH_KEY=~/.ssh/id_ed25519_vps 覆盖密钥路径
# ============================================================================
set -uo pipefail
IP="${1:?用法: vps-route-check.sh <VPS_IP> [SSH端口] [国内目标IP]}"
PORT="${2:-22}"
TARGET="${3:-114.114.114.114}"
case "$TARGET" in ''|*[!0-9A-Za-z.:-]*) echo "国内目标不合法: $TARGET"; exit 2 ;; esac
case "$PORT" in ''|*[!0-9]*) echo "SSH 端口不合法: $PORT"; exit 2 ;; esac
KEY="${SSH_KEY:-}"
if [ -z "$KEY" ]; then
  for k in "$HOME/.ssh/id_ed25519_vps" "$HOME"/.ssh/id_ed25519_* \
           "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
    [ -f "$k" ] || continue
    case "$k" in *.pub) continue ;; esac
    KEY="$k"; break
  done
fi
# 用字符串而非数组：macOS 自带 bash 3.2 在 set -u 下空数组展开会报 unbound
KEYOPT=""; [ -n "$KEY" ] && KEYOPT="-i $KEY"
SSHOPT="$KEYOPT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes -o LogLevel=ERROR -p $PORT"

# 跨平台超时执行（macOS 无 timeout 命令）
run_to(){ local secs=$1; shift; perl -e 'alarm shift; exec @ARGV' "$secs" "$@" 2>/dev/null; }

# ASN 判定表
annotate(){
  sed -E \
    -e 's/AS9929/AS9929[联通CUII精品]/g' \
    -e 's/AS4809/AS4809[电信CN2]/g' \
    -e 's/AS58807/AS58807[联通国际CUG]/g' \
    -e 's/AS10099/AS10099[联通国际CUG]/g' \
    -e 's/AS4837/AS4837[联通163]/g' \
    -e 's/AS4134/AS4134[电信163]/g' \
    -e 's/AS58453/AS58453[移动CMI]/g' \
    -e 's/AS23764/AS23764[电信CTG]/g'
}

echo "=============== 线路体检: $IP → 国内 $TARGET ==============="
echo ""

# ---------------------------------------------------------------- 去程
echo "--- 1. 去程路由（本机 → VPS，注：决定上传/请求体验）---"
if ! command -v traceroute >/dev/null; then
  echo "  (缺少 traceroute，跳过)"
else
  # Clash TUN 会接管默认路由并吞掉 traceroute 的 UDP 探测，绑定物理网卡绕开
  PHYS=$(netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $NF}' | grep -E '^en[0-9]' | head -1)
  TOPT=""
  [ -n "$PHYS" ] && TOPT="-i $PHYS"
  OUT=$(run_to 75 traceroute $TOPT -a -n -w 2 -q 1 -m 18 "$IP")
  echo "$OUT" | annotate | sed 's/^/  /'
  if echo "$OUT" | grep -qE '^\s*[0-9]+\s+\*$' && ! echo "$OUT" | grep -q 'AS'; then
    echo "  ⚠️ 全部超时：本机 Clash TUN 劫持了探测（绑定接口 ${PHYS:-未知} 仍失败）"
    echo "     需要去程数据时，临时关闭 TUN 后重跑本脚本"
  fi
  echo ""
  echo "  去程 AS 摘要:"
  echo "$OUT" | grep -oE 'AS[0-9]+' | sort -u | annotate | sed 's/^/    /' || echo "    (无)"
fi
echo ""

# ---------------------------------------------------------------- 回程
echo "--- 2. 回程路由（VPS → 国内，注：决定下载/流媒体体验）---"
[ "$TARGET" = "114.114.114.114" ] && echo "  提示: 用你家宽出口 IP 作第 3 参数可复核送中情况与真实落地路径"
echo "  SSH 登录并探测中（最多 120s）..."
# 优先 nexttrace（ASN + 地理 + 运营商解析质量远好于 mtr --aslookup），装不上退 mtr
RC=$(run_to 130 ssh $SSHOPT "root@$IP" bash -s 2>&1 <<REMOTE
set -u
if ! command -v nexttrace >/dev/null 2>&1; then
  NXT=\$(mktemp /tmp/nxt.XXXXXX)
  if curl -fsSL --proto '=https' --max-time 60 https://nxtrace.org/nt -o "\$NXT" 2>/dev/null && [ -s "\$NXT" ]; then
    bash "\$NXT" >/dev/null 2>&1 || true
  fi
  rm -f "\$NXT"
fi
if command -v nexttrace >/dev/null 2>&1; then
  echo "=== nexttrace（缺省 ICMP，每跳 2 探测）==="
  nexttrace -q 2 $TARGET 2>/dev/null
else
  echo "=== nexttrace 安装失败，退化为 mtr ==="
  if ! command -v mtr >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y mtr-tiny >/dev/null 2>&1 || true
  fi
  if command -v mtr >/dev/null 2>&1; then
    mtr -rwzc 10 --aslookup $TARGET 2>/dev/null
  else
    if ! command -v traceroute >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y traceroute >/dev/null 2>&1 || true
    fi
    traceroute -n -w 2 -q 1 -m 18 $TARGET 2>/dev/null
  fi
fi
REMOTE
)
RC=$(printf '%s\n' "$RC" | grep -vE '^(Warning:|Permanently added)' || true)
if [ -z "$RC" ]; then
  echo "  ⚠️ SSH 探测失败（密钥 ${KEY:-默认} 是否已安装？端口 ${PORT} 是否正确？）"
  echo "     自检: ssh ${KEYOPT:-} -p $PORT root@$IP echo OK"
else
  echo "$RC" | annotate | sed 's/^/  /'
  echo ""
  echo "  回程 AS 摘要:"
  echo "$RC" | grep -oE 'AS[0-9]+' | sort -u | annotate | sed 's/^/    /'
fi
echo ""

echo "=============== 判定参考 ==============="
echo "  精品线路: AS9929(联通CUII) / AS4809(电信CN2 GIA) / AS58807·AS10099(联通CUG)"
echo "  普通线路: AS4837(联通163) / AS4134(电信163) / AS58453(移动CMI)"
echo "  结论口径: 回程出现 9929/4809/CUG 视为优质；全程 4837 属常规但不差；纯 4134 丢包高需留意"
