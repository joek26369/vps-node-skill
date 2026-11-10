#!/bin/bash
# ============================================================================
# 外部 IP 体检（在 Mac 上运行）— 新 VPS 验收标准
# 用法: bash vps-external-ip-check.sh <IP> [端口] [--no-proxy]
# 覆盖: whois / ip-api / ipinfo / ip.sb / proxycheck / Scamalytics /
#       ip.net.coffee / AbuseIPDB / check-host TCP 连通性
# 依赖: whois（macOS 自带）/ Google Chrome 或 Chromium（headless 渲染）
# 环境: IPCHECK_PROXY=http://127.0.0.1:7897 覆盖代理端口（默认自动探测）
# ============================================================================
IP="${1:?用法: vps-external-ip-check.sh <IP> [端口] [--no-proxy]}"
PORT="${2:-80}"
NOPROXY=0
for a in "$@"; do [ "$a" = "--no-proxy" ] && NOPROXY=1; done

# ---- 代理端口自动探测（Clash Verge 默认 7897）----
if [ -n "${IPCHECK_PROXY:-}" ]; then
  PX="$IPCHECK_PROXY"
else
  PX=""
  for p in 7897 7890 7891 1087 6152; do
    if nc -z -G 1 127.0.0.1 "$p" 2>/dev/null; then PX="http://127.0.0.1:$p"; break; fi
  done
  [ -z "$PX" ] && PX="http://127.0.0.1:7897"   # 兜底
fi
[ "$NOPROXY" = "1" ] && PX=""

# ---- Chrome 路径自动探测 ----
CHROME=""
for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
         "/Applications/Chromium.app/Contents/MacOS/Chromium" \
         "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
         "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"; do
  [ -x "$c" ] && { CHROME="$c"; break; }
done

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
# 注意: 不用数组，macOS 自带 bash 3.2 在 set -u 下空数组展开会报错
CPXOPT=""; [ -n "$PX" ] && CPXOPT="-x $PX"

echo "================ 外部 IP 体检: $IP ================"
echo "  代理: ${PX:-<直连>}   浏览器: ${CHROME:-<未找到，ipinfo 项将跳过>}"
echo ""

echo "--- 1. whois 归属（ARIN 转介自动跟随）---"
if command -v whois >/dev/null; then
  W=$(whois "$IP" 2>/dev/null || true)
  if echo "$W" | grep -q "whois.arin.net"; then
    whois -h whois.arin.net "$IP" 2>/dev/null | grep -iE "OrgName|NetName|City|StateProv|Country" | head -6
  else
    echo "$W" | grep -i -E "netname|orgname|org-name|descr|country" | head -5
  fi
else
  echo "  (未安装 whois，跳过；brew install whois)"
fi

echo ""
echo "--- 2. ip-api.com (机房/代理标记) ---"
curl -s --noproxy '*' -m 10 "http://ip-api.com/json/$IP?fields=country,regionName,city,isp,org,as,asname,proxy,hosting,mobile" \
  | python3 -m json.tool 2>/dev/null || echo "  (接口不可用)"

echo ""
echo "--- 3. ipinfo.io (🔴 Anonymization 六项 / Privacy / Anycast / AS Type / ASN 详情) ---"
if [ -n "$CHROME" ]; then
  CDIR=$(mktemp -d /tmp/chrome-ipinfo.XXXXXX)
  DOMF=$(mktemp /tmp/ipinfo_dom.XXXXXX)   # BSD mktemp 要求模板以 X 结尾
  "$CHROME" --headless=new --disable-gpu --user-data-dir="$CDIR" ${PX:+--proxy-server="$PX"} \
    --virtual-time-budget=20000 --timeout=40000 --dump-dom "https://ipinfo.io/$IP" 2>/dev/null > "$DOMF"
  rm -rf "$CDIR"
  python3 << PYEOF
import re
try:
    h=open('$DOMF',encoding='utf-8',errors='ignore').read()
except Exception:
    print("  (页面抓取失败, 请浏览器复核 https://ipinfo.io/$IP)"); raise SystemExit
if 'Anonymization' not in h:
    print("  (页面未完整渲染, 请浏览器复核 https://ipinfo.io/$IP)"); raise SystemExit

t=re.sub(r'<(svg|script|style)[^>]*>.*?</\1>','',h,flags=re.S)
t=re.sub(r'<[^>]+>','\n',t).replace('&amp;','&')
lines=[l.strip() for l in t.split('\n') if l.strip()]
def nxt(label, n=1):
    for i,l in enumerate(lines):
        if l==label: return lines[i+n] if i+n < len(lines) else None
    return None

bad=[]; out=[]
for i,l in enumerate(lines):
    if l=='Anonymization':
        seq=lines[i:i+16]
        for j,name in enumerate(seq):
            if name in ('VPN','Proxy','Tor','Relay','Hosting','Residential Proxy') and j+1<len(seq):
                v=seq[j+1]; good='not detected' in v.lower()
                out.append(f'{name}:'+('✅' if good else '❌'))
                if not good: bad.append(f'{name}={v}')
        break
print('🔴 Anonymization : ' + (' · '.join(out) if out else '(区块未匹配)') + ('' if not bad else '  ⚠️ 检出: '+', '.join(bad)))

for label,tag in [('Privacy','🔴 Privacy'),('Anycast','🔴 Anycast'),('AS Type','🔴 AS Type')]:
    v=nxt(label)
    if v:
        note=''
        vl=v.lower()
        if label in ('Privacy','Anycast'):
            note=' (false=干净✅)' if vl=='false' else (' (true=异常❌)' if vl=='true' else '')
        print(f'{tag:16s}: {v}{note}')

for i,l in enumerate(lines[:-2]):
    if l=='ASN' and re.match(r'^AS\d+$', lines[i+1]):
        tail=[x for x in lines[i+2:i+5] if x not in ('—','-') and not x.startswith('#')]
        print(f'ASN 详情        : {lines[i+1]} — {tail[0] if tail else ""}')
        break
print(f'Hostname        : {nxt("Hostname")}')
print(f'Range           : {nxt("Range")}')
print(f'Company         : {nxt("Company")}')
hd=nxt('Hosted domains')
print(f'Hosted domains  : {hd}' + (' (0=无域名残留✅)' if hd=='0' else ''))
v6=None
for i,l in enumerate(lines):
    if l=='IPv6' or l.startswith('IPv6:'):
        v6=l.split(':',1)[1].strip() if ':' in l else lines[i+1]
        break
if v6: print(f'IPv6            : {v6}')
print(f'页面复核        : https://ipinfo.io/$IP')
PYEOF
  rm -f "$DOMF"
else
  echo "  (找不到 Chrome/Chromium，跳过；请手动打开 https://ipinfo.io/$IP)"
fi

echo ""
echo "--- 4. ip.sb geoip (归属交叉验证) ---"
R=$(curl -s --noproxy '*' -m 10 -A "$UA" "https://api.ip.sb/geoip/$IP")
echo "$R" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print('country:',d.get('country'),'| city:',d.get('city'),'| asn:',d.get('asn'),'| org:',d.get('organization'))
except: print('  (接口拒绝或不可用, 以 ipinfo/ip-api 结果为准)')"

echo ""
echo "--- 5. proxycheck.io (代理/VPN/风险) ---"
curl -s --noproxy '*' -m 10 "https://proxycheck.io/v2/$IP?vpn=1&asn=1&risk=1"; echo

echo ""
echo "--- 6. Scamalytics (🔴 Fraud Score / Proxies 六项 / Residential Proxy / Datacenter / 黑名单) ---"
curl -s --noproxy '*' -m 20 ${CPXOPT:-} -A "$UA" "https://scamalytics.com/ip/$IP" | python3 -c "
import sys,re
h=sys.stdin.read()
t=re.sub(r'<(script|style)[^>]*>.*?</\1>','',h,flags=re.S)
t=re.sub(r'<[^>]+>','\n',t)
t=t.replace('&larr;','<-').replace('&rarr;','->').replace('&nbsp;',' ')
lines=[l.strip() for l in t.split('\n') if l.strip()]
def pair(label):
    for i,l in enumerate(lines):
        if l==label and i+1<len(lines) and lines[i+1] in ('Yes','No'): return lines[i+1]
    return None
score=None
for l in lines:
    m=re.match(r'Fraud Score:\s*(\d+)',l)
    if m: score=int(m.group(1)); break
risk=next((l for l in lines if re.fullmatch(r'(Very High|High|Elevated|Low|Very Low) Risk', l)), None)
if score is not None:
    bar='#'*(score//5)+'.'*(20-score//5)
    print(f'🔴 Fraud Score  : {score}/100  [{bar}]  {risk or \"\"}')
else:
    print(f'🔴 Fraud Score  : (未匹配) {risk or \"\"}')
print('🔴 Proxies      :')
bad=[]
for name in ['Anonymizing VPN','Tor Exit Node','Server','Public Proxy','Web Proxy','Search Engine Robot']:
    v=pair(name)
    if v:
        clean=v.lower()=='no'
        note='' if clean else (' (机房IP必然为Yes, 预期内)' if name=='Server' else ' ⚠️')
        if not clean and name!='Server': bad.append(name)
        print(f'    {name:22s}: {v}{note}')
v=pair('Residential Proxy')
if v: print(f'    Residential Proxy      : {v}' + (' ✅' if v.lower()=='no' else ' ❌ (风控大忌)'))
dc=pair('Datacenter')
if dc: print(f'    Datacenter             : {dc}' + (' (机房属性, 预期内)' if dc.lower()=='yes' else ''))
print('    External Blacklists:')
bl_bad=[]
for name in ['Firehol','IP2ProxyLite','IPsum','Spamhaus','X4Bnet Spambot']:
    v=pair(name)
    if v:
        clean=v.lower()=='no'
        if not clean: bl_bad.append(name)
        print(f'    {name:22s}: {v}' + (' ✅' if clean else ' ❌'))
if not any(pair(n) for n in ['Firehol','IPsum','Spamhaus']):
    print('    (黑名单区块未匹配, 请浏览器复核 https://scamalytics.com/ip/$IP)')
print(f'    小结: 代理/VPN/Tor {\"全部干净\" if not bad else \"⚠️ 检出: \"+\", \".join(bad)} | 黑名单 {\"全部干净\" if not bl_bad else \"⚠️ 被列: \"+\", \".join(bl_bad)}')"

echo ""
echo "--- 7. ip.net.coffee (聚合画像: 原生性/运营商类型/服务商/ASN/风险检测) ---"
COF="https://ip.net.coffee/api/ipv2"
LK=$(curl -s --noproxy '*' -m 15 ${CPXOPT:-} "$COF/lookup/$IP")
RAD=$(curl -s --noproxy '*' -m 15 ${CPXOPT:-} "$COF/radar/$(echo "$LK" | python3 -c "import json,sys;print(json.load(sys.stdin).get('asn',0))" 2>/dev/null)" 2>/dev/null)
DNSBL=$(curl -s --noproxy '*' -m 20 ${CPXOPT:-} "$COF/dnsbl/$IP" 2>/dev/null)
python3 << PYEOF
import json
try:
    d=json.loads('''$LK''')
except Exception:
    print("  (lookup 接口失败, 请浏览器复核 https://ip.net.coffee/ip/$IP)"); raise SystemExit
def g(k,alt='?'): return d.get(k) if d.get(k) not in (None,'',[]) else alt

reg=d.get('registered_country') or d.get('country')
native='✅ 原生IP' if d.get('registered_country_code')==d.get('countryCode') else f'⚠️ 非原生(注册地 {reg})'
print(f"IP 原生性      : {d.get('country')} | {native}")

tag='家庭住宅IP ✅' if d.get('isResidential') else ('机房IP ❌' if d.get('is_datacenter') else '中性')
print(f"标记           : {tag}")

kind=g('asn_kind'); ctype=g('company_type')
print(f"🔴 运营商类型  : ASN性质={kind} · 公司类型={ctype}")
print(f"🔴 服务商      : {g('company_name')}")
print(f"🔴 ASN 归属    : AS{d.get('asn')} {g('asOrganization')} ({g('asname')})")
print(f"ASN IPv4 总量  : {g('asn_ipv4_count')}")
print(f"预估带宽       : {g('asn_tbps')}")
print(f"ASN 注册日期   : {g('asn_allocated')}")

rdns=g('rdns','(无)')
rpki_map={'notfound':'NotFound(未声明)','valid':'Valid✅','invalid':'Invalid❌','unknown':'未知'}
rpki=rpki_map.get(g('rpki_status'), g('rpki_status'))
print(f"技术指标       : Bogon={'是(异常)' if d.get('is_bogon') else '否(公网可达)'} · rDNS={rdns} · RPKI={rpki}")
print(f"滥用等级       : {g('abuser_score')}")
try:
    db=json.loads('''$DNSBL''')
    rs=db.get('results',[])
    listed=[r['engine'] for r in rs if r.get('listed')]
    print(f"DNSBL 黑名单   : {len(rs)-len(listed)}/{len(rs)} 家纯净" + (f" ⚠️ 被列: {listed}" if listed else ""))
except: pass

print(f"风险深度检测   : VPN={'检出❌' if d.get('is_vpn') else '未检测到✅'} · 代理={'检出❌' if d.get('is_proxy') else '未检测到✅'} · Tor={'检出❌' if d.get('is_tor') else '未检测到✅'} · 爬虫={'检出❌' if d.get('is_crawler') else '未检测到✅'} · Abuser={'是❌' if d.get('is_abuser') else '否✅'} · Mobile={d.get('is_mobile')}")

ai=g('ai_verdict')
if isinstance(ai,dict):
    print(f"AI 综合判定    : {ai.get('label')} (置信度 {ai.get('confidence')}%) | {ai.get('reasoning','')}")
print(f"信任评分       : {g('trust_score')}/100")

try:
    r=json.loads('''$RAD''')
    print(f"人机流量       : 人类 {r.get('human')}% · 机器 {r.get('bot')}% (28天)")
except: pass
print(f"页面复核       : https://ip.net.coffee/ip/$IP")
PYEOF

echo ""
echo "--- 8. AbuseIPDB (滥用举报) ---"
curl -s --noproxy '*' -m 20 ${CPXOPT:-} -A "$UA" "https://www.abuseipdb.com/check/$IP" | python3 -c "
import sys,re
h=sys.stdin.read()
conf=re.search(r'was reported\s*<b>(\d+)</b> times',h) or re.search(r'reported\s*(\d+)\s*times',h)
score=re.search(r'confidence of abuse[^0-9]*(\d+)%',h, re.I) or re.search(r'(\d+)%\s*confidence',h, re.I)
print('  被举报次数:', conf.group(1) if conf else '0/未匹配', '| 滥用置信度:', (score.group(1)+'%') if score else '低/未匹配')
if 'cloudflare' in h.lower() and not conf: print('  (可能被 CF 挑战, 请浏览器复核 https://www.abuseipdb.com/check/$IP)')"

echo ""
echo "--- 9. TCP $PORT 连通性（check-host 国际视角）---"
R=$(curl -s --noproxy '*' -m 15 -H "Accept: application/json" "https://check-host.net/check-tcp?host=$IP:$PORT&max_nodes=6")
RID=$(echo "$R" | python3 -c "import json,sys;print(json.load(sys.stdin).get('request_id',''))" 2>/dev/null)
RES=""
for i in 1 2 3 4 5 6; do
  sleep 10
  RES=$(curl -s --noproxy '*' -m 15 -H "Accept: application/json" "https://check-host.net/check-result/$RID")
  DONE=$(echo "$RES" | python3 -c "
import json,sys
d=json.load(sys.stdin)
vals=[v for k,v in d.items() if k not in ('nodes','request_id','permanent_link')]
print('yes' if any(v is not None for v in vals) else 'no')" 2>/dev/null)
  [ "$DONE" = "yes" ] && break
done
echo "$RES" | python3 -c "
import json,sys
d=json.load(sys.stdin)
res={k:v for k,v in d.items() if k not in ('nodes','request_id','permanent_link')}
ok=fail=pending=0; rows=[]
for k,v in res.items():
    if v is None: rows.append(f'  {k}: pending'); pending+=1; continue
    if isinstance(v,list) and v and isinstance(v[0],dict):
        if 'error' in v[0]:
            e=v[0]['error']
            if 'refused' in e: rows.append(f'  {k}: REFUSED (路径通, 无监听)'); ok+=1
            elif 'timed out' in e: rows.append(f'  {k}: TIMEOUT (可能被墙)'); fail+=1
            else: rows.append(f'  {k}: {e}'); fail+=1
        else: rows.append(f'  {k}: OK ({v[0].get(\"time\",\"?\")}s)'); ok+=1
print(f'国际节点 TCP $PORT: ok={ok} fail={fail} pending={pending}')
print('\n'.join(rows) if rows else '  (结果未就绪, 稍后人工复核)')
print('  链接: https://check-host.net/check-result/$RID')" 2>/dev/null || echo "  (解析失败, 请打开 https://check-host.net/check-tcp?host=$IP:$PORT)"
echo "  ⚠️ 国内视角请人工打开: https://tcp.ping.pe/$IP:$PORT （JS 渲染，无法自动抓取；看 CN 行 ok/fail）"
echo "  注: 80 REFUSED 属正常（无监听）；443 的国内可达性由实际使用持续验证"

echo ""
echo "================ 体检结束 ================"
echo "判定参考: 全库 US 无送中 | 家宽/ISP 判定 >=4/5 | Scamalytics < 25 | AbuseIPDB 举报 0 | 国内 TCP 通畅"
