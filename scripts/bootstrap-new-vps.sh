#!/bin/bash
# ============================================================================
# 新 VPS 一键上线（在 Mac 上运行）— 编排器
# 用法:
#   bash bootstrap-new-vps.sh <IP> <SSH端口> <root密码> <duckdns子域名> <duckdns_token> [dest]
# 示例:
#   bash bootstrap-new-vps.sh 1.2.3.4 2222 'MyP@ss' <YOUR_DUCKDNS_SUB> <YOUR_DUCKDNS_TOKEN>
#
# 前提:
#   - duckdns.org 已登录，且已在 Domains 框添加了 <duckdns子域名>
#   - 本机有 expect（brew install expect）
#
# 流程: 预检(验货，含 IP 风险体检) → 部署初始化 → 存凭据 → 装密钥 → 安全加固 → 导入 Verge
# 环境变量:
#   WHITELIST_IP=家宽出口IP   加入 fail2ban 白名单
#   HARDEN_UPGRADE=0          跳过系统补丁升级（快很多）
#   SKIP_IPAUDIT=1            跳过预检里的 9 项 IP 体检（快 1-2 分钟）
#   SKIP_PRECHECK=1           跳过部署前预检（不建议）
#   FORCE=1                   预检判 FAIL 时仍强制部署
#   DEST=www.paypal.com       REALITY 借壳站点（第 6 参数，优先级更高）
# ============================================================================
set -euo pipefail

IP="${1:?用法: bootstrap-new-vps.sh <IP> <SSH端口> <密码> <duckdns子域名> <duckdns_token> [dest]}"
PORT="${2:?need ssh port}"
PASS="${3:?need root password}"
DSUB="${4:?need duckdns subdomain}"
DTOK="${5:?need duckdns token}"
DEST="${6:-${DEST:-www.paypal.com}}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP=$(date +%Y%m%d-%H%M)
WORK=$(mktemp -d /tmp/vpsboot.XXXXXX)
CREDDIR="$HOME/.vps-node"
mkdir -p "$CREDDIR"; chmod 700 "$CREDDIR"

# ---------- 依赖检查 ----------
for b in expect ssh scp; do
  command -v "$b" >/dev/null || { echo "缺少 ${b}（macOS: brew install ${b}）"; exit 1; }
done

# ---------- expect 助手（密码 SSH）----------
cat > "$WORK/sshx.exp" <<EOF
#!/usr/bin/expect -f
set timeout 1500
set port [lindex \$argv 0]; set cmd [lindex \$argv 1]
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -p \$port root@${IP} \$cmd
expect {
  "password:" { send "${PASS}\r"; exp_continue }
  "Permission denied" { exit 1 }
  eof
}
EOF
cat > "$WORK/scpx.exp" <<EOF
#!/usr/bin/expect -f
set timeout 120
set port [lindex \$argv 0]; set src [lindex \$argv 1]; set dst [lindex \$argv 2]
spawn scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P \$port \$src root@${IP}:\$dst
expect {
  "password:" { send "${PASS}\r"; exp_continue }
  eof
}
EOF
chmod +x "$WORK/sshx.exp" "$WORK/scpx.exp"
trap 'rm -rf "$WORK"' EXIT

# ---------- 1. 预检（验货，不装任何东西）----------
echo "== [1/6] 预检：这台机器和这个 IP 值不值得留 =="
echo ""
PX_RC=0
if [ "${SKIP_PRECHECK:-0}" = "1" ]; then
  echo "  SKIP_PRECHECK=1，已跳过（不建议：没验货就装机，坏机器也会被装成节点）"
else
  PXTARGET="${HOME_IP:-114.114.114.114}"
  PXARG=""
  [ "${SKIP_IPAUDIT:-0}" = "1" ] || PXARG="--ipaudit"
  set +e
  TARGET="$PXTARGET" SKIP_SPEED="${SKIP_SPEED:-0}" \
    bash "$HERE/vps-precheck.sh" "$IP" "$PORT" "$PASS" $PXARG 2>&1 | sed 's/^/  /'
  PX_RC=${PIPESTATUS[0]}
  set -e
  echo ""
  case "$PX_RC" in
    0) echo "  ── 预检通过，进入部署 ──" ;;
    1) echo "  ── 有警告，但可以部署。10 秒后继续（Ctrl-C 中断去换机器）──"
       sleep 10 ;;
    *)
       echo "  ── 预检未通过：这台机器 / 这个 IP 不建议做代理节点 ──"
       echo "     建议先联系商家：换 IP、换节点、或退款。"
       echo "     确认仍要部署（比如你已知这些警告无所谓）："
       echo "       FORCE=1 bash $0 $IP $PORT '<密码>' $DSUB $DTOK"
       echo "     只想看预检不部署："
       echo "       bash $HERE/vps-precheck.sh $IP $PORT '<密码>'"
       exit 2 ;;
  esac
fi
echo ""

# ---------- 2. 上传并执行初始化 ----------
echo "== [2/6] 上传并执行 vps-node-init.sh（约 2-4 分钟）=="
$WORK/scpx.exp "$PORT" "$HERE/vps-node-init.sh" /root/vps-node-init.sh 2>&1 | grep -vE 'Warning|spawn' || true
INITLOG="/tmp/vps-init-$STAMP.log"
$WORK/sshx.exp "$PORT" "bash /root/vps-node-init.sh $IP $DSUB $DTOK $DEST" 2>&1 \
  | grep -vE 'Warning|spawn' | tee "$INITLOG"

# ---------- 3. 解析结果 + 存凭据 ----------
echo "== [3/6] 保存凭据 =="
RESULT=$(grep -o 'VPS_RESULT_JSON=.*' "$INITLOG" | tail -1 | sed 's/^VPS_RESULT_JSON=//' || true)
if [ -n "${RESULT:-}" ] && echo "$RESULT" | python3 -m json.tool >/dev/null 2>&1; then
  echo "$RESULT" | python3 -m json.tool > "$CREDDIR/$DSUB.json"
  # 记录部署日：周检 prompt 用它算观察期结束日（部署 + 7 天）
  python3 - "$CREDDIR/$DSUB.json" <<'PY'
import json, sys, datetime
p = sys.argv[1]
d = json.load(open(p, encoding='utf-8'))
d.setdefault('deploy_date', datetime.date.today().isoformat())
json.dump(d, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
  chmod 600 "$CREDDIR/$DSUB.json"
  echo "  凭据: $CREDDIR/$DSUB.json"
  SUBURL=$(echo "$RESULT" | python3 -c "import json,sys;print(json.load(sys.stdin).get('sub_url',''))")
else
  SUBURL=$(grep -oE "https://${DSUB}\.duckdns\.org:2096/[a-f0-9]+\.yaml" "$INITLOG" | head -1 || true)
  [ -n "$SUBURL" ] && echo "  ⚠️ 结构化结果缺失，已从日志回退解析"
fi
cp "$INITLOG" "$CREDDIR/$DSUB-$STAMP.log"; chmod 600 "$CREDDIR/$DSUB-$STAMP.log"
echo "  部署日志: $CREDDIR/$DSUB-$STAMP.log"
if [ -z "${SUBURL:-}" ]; then
  echo "  ❌ 未能取得订阅 URL，后续步骤中止（检查日志）"; exit 1
fi
echo "  订阅 URL: $SUBURL"

# ---------- 4. 安装 SSH 密钥（替换密码登录）----------
echo "== [4/6] 安装 SSH 密钥 =="
KEYF="$HOME/.ssh/id_ed25519_vps"
[ -f "$KEYF" ] || ssh-keygen -t ed25519 -f "$KEYF" -N "" -C "vps-$DSUB" >/dev/null
PUB=$(cat "$KEYF.pub")
$WORK/sshx.exp "$PORT" "mkdir -p /root/.ssh && chmod 700 /root/.ssh && { grep -qF '$PUB' /root/.ssh/authorized_keys 2>/dev/null || echo '$PUB' >> /root/.ssh/authorized_keys; }; chmod 600 /root/.ssh/authorized_keys; sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config; sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config; sshd -t && systemctl restart ssh && echo KEYINSTALLED" 2>&1 \
  | grep -E "KEYINSTALLED" || true
if ssh -i "$KEYF" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o PasswordAuthentication=no -o ConnectTimeout=10 -o BatchMode=yes -p "$PORT" "root@$IP" 'echo KEY_LOGIN_OK' 2>/dev/null | grep -q KEY_LOGIN_OK; then
  echo "  ✅ 密钥登录通过"
else
  echo "  ❌ 密钥登录失败，中止（避免加固后失联）"; exit 1
fi

# ---------- 5. 安全加固 ----------
echo "== [5/6] 安全加固（ufw / SSH 收敛 / sysctl / fail2ban）=="
$WORK/scpx.exp "$PORT" "$HERE/vps-harden.sh" /root/vps-harden.sh 2>&1 | grep -vE 'Warning|spawn' || true
HARDEN_ARGS=""; [ "${HARDEN_UPGRADE:-1}" = "0" ] && HARDEN_ARGS="--no-upgrade"
HL="/tmp/vps-harden-$STAMP.log"
ssh -i "$KEYF" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p "$PORT" "root@$IP" \
  "SSH_PORT=$PORT WHITELIST_IP=${WHITELIST_IP:-} bash /root/vps-harden.sh $HARDEN_ARGS" 2>&1 \
  | tee "$HL" | grep -E "===|✅|⚠️|规则|ufw|fail2ban|内核|待升级|加固完成" | tail -30
if grep -q "reboot-required 存在" "$HL"; then
  echo "  ⚠️ 有内核/系统更新需重启生效: ssh -p $PORT root@$IP 'systemctl reboot'"
fi
cp "$HL" "$CREDDIR/$DSUB-harden-$STAMP.log"; chmod 600 "$CREDDIR/$DSUB-harden-$STAMP.log"

# ---------- 6. 导入 Clash Verge ----------
echo "== [6/6] 导入 Clash Verge =="
ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$SUBURL")
if [ "$(uname)" = "Darwin" ]; then
  open "clash://install-config?url=${ENC}&name=${DSUB}-VPS" && echo "  已发送导入请求"
else
  echo "  请手动导入订阅: $SUBURL"
fi

echo ""
echo "================= 部署完成 ================="
echo "订阅 URL : $SUBURL"
echo "凭据     : $CREDDIR/$DSUB.json"
echo ""
echo "接下来按顺序做（验收没全绿之前，不要装哨兵）:"
echo "  1. Clash Verge → 配置 → 点击 '${DSUB}-VPS' 卡片激活"
echo "  2. 验收: bash $HERE/vps-verify.sh $IP --browser          # 必须全绿"
echo "  3. 线路体检（可选）: bash $HERE/vps-route-check.sh $IP $PORT [家宽IP]"
echo "  4. 验收通过后装哨兵: bash $HERE/vps-sentinel-install.sh $DSUB --home-ip <家宽出口IP>"
echo "  5. 建两条 automation（日检 + 周检）: bash $HERE/vps-automation-spec.sh $DSUB"
echo "============================================"
