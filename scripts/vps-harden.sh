#!/bin/bash
# ============================================================================
# VPS 安全加固（P0-P4）
# P0 ufw 防火墙 / P1 系统补丁 / P2 SSH 收敛 / P3 sysctl 网络加固 / P4 fail2ban
# 用法: SSH_PORT=22 WHITELIST_IP=192.0.2.10 bash vps-harden.sh [--no-upgrade]
# 特性: 幂等；防火墙先放行 SSH 再启用（防自锁）；每步有校验输出
# ============================================================================
set -uo pipefail
SSH_PORT="${SSH_PORT:-22}"
WHITELIST_IP="${WHITELIST_IP:-}"      # 可选：你的家宽出口 IP，加入 fail2ban 白名单
SUB_PORT="${SUB_PORT:-2096}"          # 订阅端点端口
DO_UPGRADE=1
for a in "$@"; do [ "$a" = "--no-upgrade" ] && DO_UPGRADE=0; done

ok(){ echo "  ✅ $*"; }
warn(){ echo "  ⚠️  $*"; }
hdr(){ echo; echo "=== $* ==="; }

# 订阅服务单元名自动探测（兼容历史命名）
SUBUNIT="vps-sub-https"
if ! systemctl list-unit-files 2>/dev/null | grep -q '^vps-sub-https\.service'; then
  for u in node-sub-https v2ray-sub-https sub-https; do
    systemctl list-unit-files 2>/dev/null | grep -q "^${u}\.service" && { SUBUNIT="$u"; break; }
  done
fi

hdr "0. 前置检查"
command -v ufw >/dev/null || { echo "  安装 ufw..."; DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >/dev/null 2>&1; }
echo "  系统: $(. /etc/os-release; echo "$PRETTY_NAME")  内核: $(uname -r)"
echo "  SSH 端口: $SSH_PORT  订阅单元: $SUBUNIT"

# ---------------------------------------------------------------- P0 防火墙
hdr "P0. ufw 防火墙（放行 $SSH_PORT/tcp 443/tcp 8443/udp $SUB_PORT/tcp）"
ufw --force reset >/dev/null 2>&1
ufw default deny incoming  >/dev/null
ufw default allow outgoing >/dev/null
# 先放行 SSH（limit：30 秒内超 6 次新连接即封禁）
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate-limited)' >/dev/null
ufw allow 443/tcp            comment 'VLESS+REALITY'   >/dev/null
ufw allow 8443/udp           comment 'Hysteria2'       >/dev/null
ufw allow "$SUB_PORT/tcp"    comment 'sub endpoint'    >/dev/null
if ufw show added | grep -q "$SSH_PORT/tcp"; then
  ufw --force enable >/dev/null && ok "ufw 已启用"
else
  warn "SSH 规则缺失，拒绝启用防火墙（防锁死）"; exit 1
fi
echo "  规则:"; ufw status numbered | sed 's/^/    /'
ss -tlnp | grep -q ":$SSH_PORT " && ok "SSH 仍在监听 $SSH_PORT"

# ---------------------------------------------------------------- P2 SSH 收敛
hdr "P2. SSH 收敛"
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# 安全加固（由 vps-node skill 写入）
PermitRootLogin prohibit-password
MaxAuthTries 3
MaxSessions 4
X11Forwarding no
AllowAgentForwarding no
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no
EOF
chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf
if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl restart ssh
  sleep 1
  ok "sshd 配置校验通过并重载"
  sshd -T 2>/dev/null | grep -E "^(permitrootlogin|maxauthtries|x11forwarding|clientaliveinterval|passwordauthentication)" | sed 's/^/    /'
else
  warn "sshd 配置校验失败，已回滚"; rm -f /etc/ssh/sshd_config.d/99-hardening.conf; exit 1
fi

# ---------------------------------------------------------------- P3 sysctl
hdr "P3. sysctl 网络栈加固"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# 反欺骗 / 反重定向（sing-box 非 TUN 模式，不涉及转发）
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
# rp_filter 用 loose(2)：严格模式可能误伤代理的非对称回程
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.ip_forward = 0
EOF
sysctl -q -p /etc/sysctl.d/99-hardening.conf && ok "sysctl 已生效"
echo "    $(sysctl -n net.ipv4.tcp_congestion_control) (拥塞控制，应仍为 bbr) / rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter)"

# ---------------------------------------------------------------- P4 fail2ban
hdr "P4. fail2ban（仅 sshd${WHITELIST_IP:+，白名单 $WHITELIST_IP}）"
if ! dpkg -l fail2ban 2>/dev/null | grep -q '^ii'; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1 \
    && ok "fail2ban 已安装" || warn "fail2ban 安装失败（跳过）"
fi
if command -v fail2ban-client >/dev/null; then
  IGNORE="127.0.0.1/8 ::1"
  [ -n "$WHITELIST_IP" ] && IGNORE="$IGNORE $WHITELIST_IP"
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend = systemd
bantime  = 1h
findtime = 10m
maxretry = 4
ignoreip = $IGNORE

[sshd]
enabled = true
port    = $SSH_PORT
maxretry = 4
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  sleep 2
  if systemctl is-active --quiet fail2ban; then
    ok "fail2ban 运行中: $(fail2ban-client status sshd 2>/dev/null | grep -E 'Currently banned|Total banned' | tr '\n' ' ')"
  else
    warn "fail2ban 未启动: $(journalctl -u fail2ban -n 3 --no-pager | tail -2)"
  fi
fi

# ---------------------------------------------------------------- P1 系统补丁
if [ "$DO_UPGRADE" = "1" ]; then
  hdr "P1. 系统补丁（apt full-upgrade，保留旧配置）"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  apt-get update -qq
  BEFORE=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)
  echo "  待升级: $BEFORE 个包"
  apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" full-upgrade 2>&1 | tail -5
  AFTER=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)
  ok "升级完成，剩余待升级: $AFTER 个包"
  echo "  内核: 运行 $(uname -r) / 已装 $(ls /boot/vmlinuz-* 2>/dev/null | sed 's|.*vmlinuz-||' | sort -V | tail -1)"
  [ -f /var/run/reboot-required ] && warn "需要重启才能生效（/var/run/reboot-required 存在）"
fi

# ---------------------------------------------------------------- 收尾校验
hdr "收尾校验"
systemctl is-active --quiet sing-box        && ok "sing-box 运行中"    || warn "sing-box 异常"
systemctl is-active --quiet "$SUBUNIT"      && ok "$SUBUNIT 运行中"    || warn "$SUBUNIT 异常"
ss -tlnp | grep -qE ":(443|$SUB_PORT) "     && ok "443 / $SUB_PORT 仍在监听"
echo
echo "=== 加固完成 ==="
