#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 NodeQuality 完整日志（含 xykt 三段报告）抽出结构化指标，输出 JSON。

用法: python3 vps-quality-parse.py <质量日志> [-o metrics.json]

设计要点:
- 只依赖标准库；日志里有大量 ANSI / \\r 进度刷新 / 盲文进度条，先清洗再匹配
- **按报告分段解析**：硬件段 / IP 段 / 网络段各自切片，避免「北京」这类词在回程
  段落里被误匹配成延迟（早期版本踩过：京 174/157/177 被解析成 54/154/29）
- 每项指标独立判定，抽不到就 null —— 上游改版只少字段，不整体崩
"""
import json
import re
import sys

BRAILLE = re.compile(r'[\u2800-\u28ff\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f]')


def clean(text):
    """去 ANSI、取每行最后一个 \\r 之后的内容、抹掉盲文进度符、丢掉纯进度行。"""
    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
    out = []
    for ln in text.split('\n'):
        ln = ln.split('\r')[-1]
        ln = BRAILLE.sub(' ', ln)
        ln = ln.strip()
        if ln and not re.fullmatch(r'[.#\-%\s\d]*', ln):
            out.append(ln)
    return '\n'.join(out)


def section(t, start, end=None):
    i = t.find(start)
    if i < 0:
        return ''
    j = t.find(end, i + len(start)) if end else -1
    return t[i:j] if j > i else t[i:]


def grab(pattern, text, flags=0):
    if not text:
        return None
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def num(x):
    if x is None:
        return None
    try:
        return int(float(str(x).replace(',', '').strip()))
    except (TypeError, ValueError):
        return None


def fnum(x):
    if x is None:
        return None
    try:
        return float(str(x).replace(',', '').replace('%', '').strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- 硬件段
def parse_hardware(s):
    return {
        'virt': grab(r'容器/虚拟化：\s*(.+?)\s*$', s, re.M),
        'os': grab(r'操作系统/内核：\s*(.+?)\s*$', s, re.M),
        'cpu': grab(r'CPU：\s*(.+?)\s+步进', s) or grab(r'CPU：\s*(.+?)\s*$', s, re.M),
        'cores': num(grab(r'(\d+)\s*核心', s)),
        'mhz': fnum(grab(r'([\d.]+)\s*MHz', s)),
        'mem_total_mb': num(grab(r'总容量\s*(\d+)\s*MB', s)),
        'mem_used_pct': num(grab(r'已用\s*\d+\s*MB\((\d+)%\)', s)),
        # ✔ = 被检测到超开手段；✘ = 未发现（好事）
        'overcommit': ('✔' in (grab(r'超开指标：(.+)', s) or '')),
        'disk_total': grab(r'总容量\s*(\d+[GT])', s),
        'disk_used': grab(r'已用容量\s*(\d+(?:\.\d+)?[GT])', s),
        'disk_used_pct': num(grab(r'已用容量\s*\S+?\((\d+)%\)', s)),
        'uptime': grab(r'运行时间：\s*(.+?)\s*$', s, re.M),
    }


# ---------------------------------------------------------------- IP 段
def parse_ip(s):
    d = {
        'asn': grab(r'自治系统号：\s*(AS\d+)', s),
        'org': grab(r'组织：\s*(.+?)\s*$', s, re.M),
        'city': grab(r'城市：\s*(.+?)\s*$', s, re.M),
        'ip_type': grab(r'IP类型：\s*(\S+)', s),
        'scamalytics': num(grab(r'Scamalytics：\s*(\d+)', s)),
        'abuseipdb': num(grab(r'AbuseIPDB：\s*(\d+)', s)),
        'ip2location': num(grab(r'IP2Location：\s*(\d+)', s)),
        'ipqs': num(grab(r'IPQS：\s*(\d+)', s)),
        'ipapi_pct': fnum(grab(r'ipapi：\s*([\d.]+)%', s)),
        'port25': grab(r'本地25端口出站：\s*(\S+)', s),
        'blacklist': grab(r'IP地址黑名单数据库：\s*(.+?)\s*$', s, re.M),
    }
    svc = grab(r'服务商：\s*(.+?)\s*$', s, re.M)
    stt = grab(r'状态：\s*(.+?)\s*$', s, re.M)
    d['unlock'] = {}
    if svc and stt:
        names, states = svc.split(), stt.split()
        for i, n in enumerate(names):
            if i < len(states):
                d['unlock'][n] = states[i]
    return d


# ---------------------------------------------------------------- 网络段
CITY_SHORT = [('北京', '京'), ('上海', '沪'), ('广州', '粤')]
INTL_CITIES = ('东京', '香港', '新加坡', '悉尼', '洛杉矶', '纽约',
               '法兰克福', '伦敦', '阿姆斯特丹', '圣保罗')


def parse_net(s):
    d = {}
    # 三网 TCP 大包延迟：切片到「四、三网TCP」→「五、三网回程」之间，
    # 表头那行本身就带着京 174/157/177，粤 可能出现在行中间，所以按城市名就地取数
    i = s.find('三网TCP')
    j = s.find('五、', i + 1) if i >= 0 else -1
    blk = s[i:j] if i >= 0 and j > i else ''
    lat = {}
    for full, short in CITY_SHORT:
        m = re.search(short + r'\s+(\d{2,4})\s+(\d{2,4})\s+(\d{2,4})', blk)
        if m:
            lat[short] = {'ct': num(m.group(1)), 'cu': num(m.group(2)), 'cm': num(m.group(3))}
    d['lat'] = lat

    # 国际互连：七、国际互连 之后；城市可能出现在行中间（一行两个城市）
    intl = {}
    idx = s.find('国际互连')
    seg = s[idx:] if idx >= 0 else ''
    for city in INTL_CITIES:
        m = re.search(city + r'\s+(\d+)\b', seg)
        if m:
            intl[city] = num(m.group(1))
    d['intl'] = intl

    back = [ln.strip() for ln in s.split('\n') if re.match(r'^(北京|上海|广州)(TCP|UDP)：', ln.strip())]
    d['backroute'] = back[:3]
    d['speedtest_all_error'] = bool(re.search(r'ERROR\s+ERROR', s)) and 'Mbps' in s
    return d


def main():
    if len(sys.argv) < 2:
        print('用法: vps-quality-parse.py <质量日志> [-o out.json]', file=sys.stderr)
        return 2
    path = sys.argv[1]
    out = None
    mode = None
    if '-o' in sys.argv:
        out = sys.argv[sys.argv.index('-o') + 1]
    if '--mode' in sys.argv:
        mode = sys.argv[sys.argv.index('--mode') + 1]
    raw = open(path, encoding='utf-8', errors='replace').read()
    t = clean(raw)

    hw = section(t, '硬件质量体检报告', 'IP质量体检报告')
    ip = section(t, 'IP质量体检报告', '网络质量体检报告')
    net = section(t, '网络质量体检报告', '正在运行回程路由追踪')

    # 模式无法从远端输出反推（日志里只有交互提示，不含实际选择），由调用方显式传入
    if not mode:
        mode = 'unknown'

    data = {
        'log': path,
        'mode': mode,
        'stamp': '',
        'hardware': parse_hardware(hw),
        'ip': parse_ip(ip),
        'net': parse_net(net),
        'report_links': sorted(set(re.findall(
            r'https://Report\.Check\.Place/(?:hardware|ip|net)/[A-Za-z0-9]+\.svg', raw))),
        'nodequality': grab(r'(https://nodequality\.com/r/[A-Za-z0-9]+)', raw),
    }
    m = re.search(r'(\d{8}-\d{4})', path)
    data['stamp'] = m.group(1) if m else ''

    js = json.dumps(data, ensure_ascii=False, indent=2)
    if out:
        with open(out, 'w', encoding='utf-8') as f:
            f.write(js + '\n')
        print(f'已写出 {out}', file=sys.stderr)
    else:
        print(js)
    return 0


if __name__ == '__main__':
    sys.exit(main())
