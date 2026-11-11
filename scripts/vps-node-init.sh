#!/bin/bash
# ============================================================================
# VPS 节点初始化（在 VPS 上以 root 运行）
# 用法: bash vps-node-init.sh <公网IP> <duckdns子域名> <duckdns_token> [dest域名]
# 示例: bash vps-node-init.sh 203.0.113.10 <YOUR_DUCKDNS_SUB> <YOUR_DUCKDNS_TOKEN> www.example.com
# 功能: BBR + sing-box(REALITY 443 + Hysteria2 8443) + Let's Encrypt(DNS-01)
#       + HTTPS 订阅端点(:2096，token 路径) + 自动续期
# 输出: 末尾打印 VPS_RESULT_JSON={...} 供编排器解析
# ============================================================================
set -euo pipefail

VIP="${1:?need public ip}"
SUB="${2:?need duckdns subdomain}"
DTOKEN="${3:?need duckdns token}"
DEST="${4:-www.paypal.com}"
FQDN="${SUB}.duckdns.org"
SUBTOKEN=$(openssl rand -hex 10)
SUBDIR=/opt/vps-sub

echo "=== [0/8] 参数: IP=$VIP domain=$FQDN dest=$DEST ==="

# 1. 依赖
echo "=== [1/8] 依赖 ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq curl openssl python3 cron ca-certificates >/dev/null 2>&1
mkdir -p /etc/sing-box "$SUBDIR" /opt/vps-certs

# 2. BBR + 内核参数
echo "=== [2/8] BBR ==="
cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
net.ipv4.tcp_mtu_probing=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
EOF
sysctl --system >/dev/null 2>&1
echo "  cc=$(sysctl -n net.ipv4.tcp_congestion_control)"

# 3. sing-box 最新版
echo "=== [3/8] sing-box ==="
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  SARCH="amd64" ;;
  aarch64|arm64) SARCH="arm64" ;;
  *) echo "FATAL: 不支持的架构 $ARCH"; exit 1 ;;
esac
VER=$(curl -s --max-time 15 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
      | grep -o '"tag_name": *"v[^"]*"' | cut -d'"' -f4 | sed 's/v//' || true)
if [ -z "${VER:-}" ]; then
  # 兜底：解析 latest 重定向 URL 里的 tag
  VER=$(curl -sI --max-time 15 https://github.com/SagerNet/sing-box/releases/latest \
        | grep -i '^location:' | sed 's#.*/tag/v##' | tr -d '\r\n')
fi
[ -n "${VER:-}" ] || { echo "FATAL: 无法确定 sing-box 版本"; exit 1; }
echo "  version=$VER arch=$SARCH"
curl -fsSL --max-time 180 "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${SARCH}.tar.gz" -o /tmp/sb.tgz
tar -xzf /tmp/sb.tgz -C /tmp
install -m 755 /tmp/sing-box-*/sing-box /usr/local/bin/sing-box
rm -rf /tmp/sb.tgz /tmp/sing-box-*
echo "  installed $(/usr/local/bin/sing-box version | head -1)"

# 4. 生成凭据
echo "=== [4/8] 凭据 ==="
UUID=$(/usr/local/bin/sing-box generate uuid)
KPEX=$(/usr/local/bin/sing-box generate reality-keypair)
PRIV=$(echo "$KPEX" | grep PrivateKey | awk '{print $2}')
PUB=$(echo "$KPEX"  | grep PublicKey  | awk '{print $2}')
SHORTID=$(openssl rand -hex 8)
HY2PASS=$(openssl rand -base64 16)
# Hy2 自签证书（不依赖域名，客户端 skip-cert-verify）
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /etc/sing-box/hy2.key -out /etc/sing-box/hy2.crt -days 3650 \
  -subj "/CN=www.bing.com" 2>/dev/null
echo "  uuid=$UUID  short_id=$SHORTID  pub=${PUB:0:12}..."

# 5. sing-box 配置（REALITY + Hy2）
echo "=== [5/8] sing-box 配置 ==="
# 配置含 REALITY 私钥 / Hy2 密码，只给 root 读
( umask 077; : > /etc/sing-box/config.json )
chmod 600 /etc/sing-box/config.json /etc/sing-box/hy2.key
cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": 443,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "$DEST",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$DEST", "server_port": 443 },
          "private_key": "$PRIV",
          "short_id": [ "$SHORTID" ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": 8443,
      "users": [ { "password": "$HY2PASS" } ],
      "tls": {
        "enabled": true,
        "server_name": "www.bing.com",
        "alpn": [ "h3" ],
        "certificate_path": "/etc/sing-box/hy2.crt",
        "key_path": "/etc/sing-box/hy2.key"
      },
      "masquerade": "https://www.bing.com"
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "final": "direct" }
}
EOF
/usr/local/bin/sing-box check -c /etc/sing-box/config.json && echo "  config OK"
# tar.gz 发行包只有二进制，没有 systemd unit；不存在就补一个
if [ ! -f /etc/systemd/system/sing-box.service ] && [ ! -f /lib/systemd/system/sing-box.service ] \
   && [ ! -f /usr/lib/systemd/system/sing-box.service ]; then
  cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
fi
systemctl daemon-reload
systemctl enable sing-box >/dev/null 2>&1
systemctl restart sing-box

# 6. Clash 订阅 YAML
echo "=== [6/8] Clash YAML ==="
# 重跑时清掉旧 token 的订阅文件，避免新链接返回旧凭据
rm -f "$SUBDIR"/*.yaml
( umask 077; : > "$SUBDIR/${SUBTOKEN}.yaml" )
cat > "$SUBDIR/${SUBTOKEN}.yaml" <<EOF
# ${FQDN} (${VIP}) — REALITY + Hysteria2, mihomo / Clash Verge
proxies:
  - name: VPS-REALITY
    type: vless
    server: ${VIP}
    port: 443
    uuid: ${UUID}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${DEST}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${PUB}
      short-id: ${SHORTID}
  - name: VPS-Hy2
    type: hysteria2
    server: ${VIP}
    port: 8443
    password: ${HY2PASS}
    sni: www.bing.com
    alpn: [h3]
    skip-cert-verify: true
    udp: true
proxy-groups:
  - name: AUTO
    type: url-test
    proxies: [VPS-REALITY, VPS-Hy2]
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
  - name: Proxy
    type: select
    proxies: [AUTO, VPS-REALITY, VPS-Hy2, DIRECT]
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF

# 7. DuckDNS + Let's Encrypt (DNS-01) + HTTPS 订阅端点
echo "=== [7/8] HTTPS 订阅 ==="
R=$(curl -s --max-time 15 "https://www.duckdns.org/update?domains=${SUB}&token=${DTOKEN}&ip=${VIP}")
echo "  duckdns -> $R"
[ "$R" = "OK" ] || { echo "FATAL: duckdns update failed（检查 token 与子域名是否已在 duckdns.org 添加）"; exit 1; }

[ -f /root/.acme.sh/acme.sh ] || curl -s https://get.acme.sh | sh -s email=admin@${FQDN} >/dev/null 2>&1
export DuckDNS_Token="$DTOKEN"
/root/.acme.sh/acme.sh --issue --dns dns_duckdns -d "$FQDN" --server letsencrypt --keylength ec-256 2>&1 | tail -3 \
  || /root/.acme.sh/acme.sh --issue --dns dns_duckdns -d "$FQDN" --server letsencrypt --keylength ec-256 --force 2>&1 | tail -3
/root/.acme.sh/acme.sh --install-cert -d "$FQDN" --ecc \
  --key-file /opt/vps-certs/key.pem --fullchain-file /opt/vps-certs/fullchain.pem \
  --reloadcmd "systemctl restart vps-sub-https 2>/dev/null || true"

cat > /opt/serve_sub_https.py <<'PYEOF'
#!/usr/bin/env python3
"""Token-path-only HTTPS subscription server (TLS 1.2+)."""
import http.server, ssl, sys, os, hmac

TOKEN = sys.argv[1]; CERT = sys.argv[2]; KEY = sys.argv[3]
PORT = int(sys.argv[4]) if len(sys.argv) > 4 else 2096
SUB_PATH = os.environ.get("SUB_PATH", "/opt/vps-sub")
HANDSHAKE_TIMEOUT = 10

def subfile():
    f = os.path.join(SUB_PATH, f"{TOKEN}.yaml")
    return f if os.path.isfile(f) else None

class H(http.server.BaseHTTPRequestHandler):
    timeout = 15          # 每连接读超时，防止慢连接占线程
    def setup(self):
        # 握手放到各自的处理线程里做，并加超时：一个空连接不会卡住 accept
        self.request.settimeout(HANDSHAKE_TIMEOUT)
        self.request.do_handshake()
        super().setup()
    def do_GET(self):
        path = self.path.split("?")[0]
        f = subfile()
        if hmac.compare_digest(path, f"/{TOKEN}.yaml") and f:
            data = open(f, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Profile-Update-Interval", "24")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "9")
            self.end_headers(); self.wfile.write(b"not found")
    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):
        pass              # 握手失败 / 超时属常态（扫描器），不刷 traceback

srv = S(("0.0.0.0", PORT), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
print(f"HTTPS sub server on :{PORT}", flush=True)
srv.serve_forever()
PYEOF

cat > /etc/systemd/system/vps-sub-https.service <<EOF
[Unit]
Description=VPS subscription HTTPS server
After=network.target

[Service]
Type=simple
Environment=SUB_PATH=${SUBDIR}
ExecStart=/usr/bin/python3 /opt/serve_sub_https.py ${SUBTOKEN} /opt/vps-certs/fullchain.pem /opt/vps-certs/key.pem 2096
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vps-sub-https >/dev/null 2>&1
systemctl restart vps-sub-https
sleep 3

# 8. 验证
echo "=== [8/8] 验证 ==="
SB=$(systemctl is-active sing-box || true)
SH=$(systemctl is-active vps-sub-https || true)
echo "sing-box : $SB"
echo "sub-https: $SH"
ss -tlnp | grep -E ':(443|2096) ' | awk '{print "  listen:", $4}' || true
SUBJ=$(echo | timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$DEST" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || echo "check failed")
echo "  443 REALITY 借壳证书: $(echo "$SUBJ" | head -c 100)"
SUBCODE=$(curl -s --max-time 12 "https://${FQDN}:2096/${SUBTOKEN}.yaml" -o /dev/null -w "%{http_code}" 2>/dev/null || true)
case "$SUBCODE" in [0-9][0-9][0-9]) ;; *) SUBCODE=000 ;; esac
SUBCODE=$((10#$SUBCODE))   # 去前导零，保证 JSON 合法（000 -> 0）
echo "  https 订阅自取: HTTP $SUBCODE"

SUBURL="https://${FQDN}:2096/${SUBTOKEN}.yaml"
echo ""
echo "================ 部署完成 ================"
echo "订阅 URL : $SUBURL"
echo "REALITY  : ${VIP}:443  uuid=${UUID}  pub=${PUB}  sid=${SHORTID}  sni=${DEST}"
echo "Hy2      : ${VIP}:8443  password=${HY2PASS}"
echo "========================================="
# 机读结果（编排器解析此行）
printf 'VPS_RESULT_JSON={"ip":"%s","fqdn":"%s","sub_url":"%s","uuid":"%s","reality_pub":"%s","short_id":"%s","dest":"%s","hy2_pass":"%s","singbox":"%s","subsvc":"%s","sub_http":%s}\n' \
  "$VIP" "$FQDN" "$SUBURL" "$UUID" "$PUB" "$SHORTID" "$DEST" "$HY2PASS" "$SB" "$SH" "$SUBCODE"
