#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
对比两次 NodeQuality 快照的 metrics.json，输出并排表和退化判定。

用法: python3 vps-quality-diff.py <基线 metrics.json> <本次 metrics.json> [--json] [--title X]

退出码: 0=无退化 / 3=存在退化项（供 automation 判断要不要提醒）
阈值集中在 RULES 里，想调松紧只改这一处。
"""
import json
import sys
import unicodedata

# 阈值：(字段, 方向, 阈值, 说明)
# 方向 up=数值变大算变差 / down=数值变小算变差 / same=不比较只展示
TH_LAT = 30      # 三网延迟漂移 ≥30ms 记退化，≥50 记严重
TH_INTL = 20     # 国际互连漂移 ≥20ms 记变化
TH_RISK = 5      # 风险分上涨 ≥5 记退化
TH_DISK = 10     # 磁盘占用上涨 ≥10% 记关注


def w(s):
    """按显示宽度（中日文字符算 2）计算，用于对齐。"""
    n = 0
    for ch in str(s):
        n += 2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1
    return n


def pad(s, width, right=False):
    s = str(s)
    gap = max(1, width - w(s))
    return (' ' * gap + s) if right else (s + ' ' * gap)


def load(p):
    with open(p, encoding='utf-8') as f:
        return json.load(f)


def g(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur or cur[k] is None:
            return default
        cur = cur[k]
    return cur


def fmt(v, unit=''):
    if v is None:
        return '—'
    if isinstance(v, float):
        v = f'{v:g}'
    return f'{v}{unit}'


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    as_json = '--json' in sys.argv
    title = '质量对比'
    if '--title' in sys.argv:
        title = sys.argv[sys.argv.index('--title') + 1]
    if len(args) < 2:
        print('用法: vps-quality-diff.py <基线 metrics.json> <本次 metrics.json>', file=sys.stderr)
        return 2

    a, b = load(args[0]), load(args[1])
    rows = []          # (指标, 基线, 本次, Δ, 判定)
    regress, improve, watch = [], [], []

    def add(name, va, vb, delta=None, verdict='', bad=False, good=False, note=''):
        rows.append((name, va, vb, delta, verdict, note))
        if bad:
            regress.append(name)
        elif good:
            improve.append(name)
        elif verdict.startswith('⚠'):
            watch.append(name)

    # ---- 硬件 ----
    for label, path, unit in [
        ('内存总量', ('hardware', 'mem_total_mb'), 'MB'),
        ('磁盘占用', ('hardware', 'disk_used_pct'), '%'),
        ('内存已用', ('hardware', 'mem_used_pct'), '%'),
    ]:
        va, vb = g(a, *path), g(b, *path)
        if va is None or vb is None:
            add(label, fmt(va, unit), fmt(vb, unit), '—', '数据缺失')
            continue
        d = vb - va
        verdict = ''
        bad = False
        if label == '内存总量':
            bad = abs(d) >= max(64, va * 0.1)
            verdict = '⚠ 规格变了' if bad else '正常'
        elif label == '磁盘占用':
            bad = d >= TH_DISK
            verdict = '⚠ 增长较快' if bad else ('改善' if d <= -TH_DISK else '正常')
        else:
            verdict = '正常'
        add(label, fmt(va, unit), fmt(vb, unit), f'{d:+d}{unit}', verdict, bad=bad)

    oa, ob = g(a, 'hardware', 'overcommit'), g(b, 'hardware', 'overcommit')
    if oa is not None and ob is not None:
        bad = (not oa) and ob
        add('超开手段', '未检出' if not oa else '检出', '未检出' if not ob else '检出',
            '', '⚠ 新出现超开' if bad else '正常', bad=bad)

    # ---- IP 风险分 ----
    for label, key, th in [('Scamalytics', 'scamalytics', TH_RISK),
                           ('AbuseIPDB', 'abuseipdb', TH_RISK),
                           ('IP2Location', 'ip2location', TH_RISK),
                           ('IPQS', 'ipqs', TH_RISK)]:
        va, vb = g(a, 'ip', key), g(b, 'ip', key)
        add(label, fmt(va), fmt(vb), '—' if va is None or vb is None else f'{vb - va:+d}',
            ('数据缺失' if va is None or vb is None else
             ('⚠ 风险上升' if vb - va >= th else ('改善' if va - vb >= th else '正常'))),
            bad=(va is not None and vb is not None and vb - va >= th))

    # ---- 解锁 ----
    ua, ub = g(a, 'ip', 'unlock', default={}), g(b, 'ip', 'unlock', default={})
    for svc in sorted(set(ua) | set(ub)):
        sa, sb = ua.get(svc), ub.get(svc)
        if sa == sb or sb is None or sa is None:
            continue
        bad = sb != '解锁' and sa == '解锁'
        good = sb == '解锁' and sa != '解锁'
        add(f'解锁·{svc}', sa, sb, '', '⚠ 掉了解锁' if bad else '恢复', bad=bad, good=good)

    # ---- 三网延迟 ----
    for city, cn in [('京', '北京'), ('沪', '上海'), ('粤', '广州')]:
        for key, cn2 in [('ct', '电信'), ('cu', '联通'), ('cm', '移动')]:
            va, vb = g(a, 'net', 'lat', city, key), g(b, 'net', 'lat', city, key)
            if va is None or vb is None:
                continue
            d = vb - va
            bad = d >= TH_LAT
            add(f'延迟·{cn}{cn2}', f'{va}ms', f'{vb}ms', f'{d:+d}ms',
                '⚠ 明显变差' if d >= 50 else ('⚠ 变差' if bad else ('改善' if d <= -TH_LAT else '正常')),
                bad=bad, good=(d <= -TH_LAT))

    # ---- 国际互连 ----
    for city in sorted(set(g(a, 'net', 'intl', default={})) & set(g(b, 'net', 'intl', default={}))):
        va, vb = g(a, 'net', 'intl', city), g(b, 'net', 'intl', city)
        if city == '洛杉矶':      # 本机所在地，1ms 无意义
            continue
        d = vb - va
        bad = d >= TH_INTL
        add(f'国际·{city}', f'{va}ms', f'{vb}ms', f'{d:+d}ms',
            '⚠ 变差' if bad else ('改善' if d <= -TH_INTL else '正常'),
            bad=bad, good=(d <= -TH_INTL))

    # ---- 输出 ----
    if as_json:
        print(json.dumps({
            'baseline': {'stamp': a.get('stamp'), 'mode': a.get('mode')},
            'current': {'stamp': b.get('stamp'), 'mode': b.get('mode')},
            'mode_mismatch': a.get('mode') != b.get('mode'),
            'rows': [{'metric': r[0], 'baseline': r[1], 'current': r[2], 'delta': r[3], 'verdict': r[4]} for r in rows],
            'regressions': regress, 'improvements': improve, 'watch': watch,
        }, ensure_ascii=False, indent=2))
        return 3 if regress else 0

    W = max([w(r[0]) for r in rows] + [10])
    print(f'{title}')
    print(f'  基线 {a.get("stamp", "?")} ({a.get("mode", "?")})  →  本次 {b.get("stamp", "?")} ({b.get("mode", "?")})')
    if a.get('mode') != b.get('mode'):
        print('  ⚠️ 两次测试模式不同（full vs lowdata），网络类数值只作趋势参考')
    print()
    print(f'  {pad("指标", W)}  {pad("基线", 10, True)}  {pad("本次", 10, True)}  {pad("变化", 9, True)}  判定')
    print('  ' + '-' * (W + 45))
    for name, va, vb, delta, verdict, _ in rows:
        print(f'  {pad(name, W)}  {pad(va, 10, True)}  {pad(vb, 10, True)}  {pad(delta, 9, True)}  {verdict}')
    print()
    line = f'  汇总: 退化 {len(regress)} 项 / 改善 {len(improve)} 项 / 关注 {len(watch)} 项'
    print(line)
    if regress:
        print(f'  🔴 退化项: {"、".join(regress)}')
    if watch:
        print(f'  🟡 关注项: {"、".join(watch)}')
    if not regress and not watch and not improve:
        print('  ✅ 各项与基线一致，无异常')
    return 3 if regress else 0


if __name__ == '__main__':
    sys.exit(main())
