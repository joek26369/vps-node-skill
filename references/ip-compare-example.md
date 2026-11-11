# ip-compare 示例报告（已脱敏）

`ip-compare.sh` v1.14.3 对 4 条住宅/代理 IP 的实测比较输出（2026-11-11）。IP 已替换为 IP-A～IP-D；标「（手动）」的数据来自 IPQuality 截图，经 `--note-db` / `--note-unlock` 手动录入。IP-A 跑的是 `--local`（含解锁检测），其余为裸 IP 快查。

```text
======== IP 比较（综合 / 家宽真实性）========
| 排名 | IP | 综合分 | 结论 | 运营商 | 类型票(家宽:机房) | 代理标记 | Scamalytics | 原生 | 黑名单 | 测试时间 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | IP-A | 76 | 待复核 | Verizon（商业线） | 5:0 | vpn/proxy | 4 | 原生 | 未列 | 2026-11-11 04:02 |
| 2 | IP-B | 61 | 待复核 | — | 5:2.5 | 无 | 25 | 原生 | 未列 | 2026-11-11 04:07 |
| 3 | IP-C | 41 | 换 | — | 6:1.5 | vpn、vpn、proxy/vpn | 0 | 原生 | 仅 PBL | 2026-11-11 04:08 |
| 4 | IP-D | 21 | 换 | — | 3:3.5 | proxy/vpn | 11 | 原生 | 命中 2 | 2026-11-11 04:09 |

======== AI 用途排名 ========
| 排名 | IP | AI适用分 | AI建议 | 综合分 | 结论 | ChatGPT | 代理标记 | Scamalytics | 类型票(家宽:机房) | 测试时间 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | IP-A | 100 | 可用 | 76 | 待复核 | 解锁 | vpn/proxy | 4 | 5:0 | 2026-11-11 04:02 |
| 2 | IP-B | 93 | 可用 | 61 | 待复核 | 解锁 | 无 | 25 | 5:2.5 | 2026-11-11 04:07 |
| 3 | IP-C | 86 | 不建议 | 41 | 换 | 解锁 | vpn、vpn、proxy/vpn | 0 | 6:1.5 | 2026-11-11 04:08 |
| 4 | IP-D | 34 | 不建议 | 21 | 换 | 解锁 | proxy/vpn | 11 | 3:3.5 | 2026-11-11 04:09 |

======== 六段汇总 ========
一、基础信息
| IP | ASN | 组织 | 城市 | 使用地 | 注册地 | 时区 | IP类型 | 登记单位 | 分配 | rDNS |
| IP-A | AS701 | UUNET | New York City | [US] United States | [US] United States | America/New_York | 原生 | Verizon Business | DIRECT ALLOCATION（直接分配） | 无 PTR |
| IP-B | AS20115 | CHARTER-20115 | Ashburn, Virginia | [US] United States | [US] United States | America/New_York | 原生 | GTT Americas, LLC | DIRECT ALLOCATION（直接分配） | 无 PTR |
| IP-C | AS11404 | AS-WAVE-1 | San Jose, Colorado | [US] United States | [US] United States | America/Los_Angeles | 原生 | BAM Broadband Opco, LLC | ALLOCATION（分配） | 无 PTR |
| IP-D | AS174 | COGENT-174 | Los Angeles, California | [US] United States | [US] United States | America/Los_Angeles | 原生 | Cogent Communications, LLC | DIRECT ALLOCATION（直接分配） | 无 PTR |

二、IP类型属性（各库使用类型）
| IP | IPinfo | ipregistry | ipapi | IP2Location | AbuseIPDB | IPLogs | ip.net.coffee | Scamalytics | ipx.al | iping.cc |
| IP-A | 未配置 | 未配置 | 未配置 | 未配置 | 未配置 | 家宽 | 家宽 | 家宽 | 家宽 | 家宽 |
| IP-B | 家宽（手动） | 家宽（手动） | 家宽（手动） | 机房（手动） | 家宽（手动） | 家宽 | 家宽 | 机房 | 家宽 | 机房 |
| IP-C | 家宽（手动） | 家宽（手动） | 家宽（手动） | 机房（手动） | 家宽（手动） | 家宽 | 家宽 | 家宽 | 家宽 | 机房 |
| IP-D | 家宽（手动） | 家宽（手动） | 家宽（手动） | 机房（手动） | 家宽（手动） | 机房 | 家宽 | 机房 | — | 机房 |

三、风险评分
| IP | IP2Location | Scamalytics | ipapi | ip.net.coffee | AbuseIPDB | IPQS | DB-IP |
| IP-A | — | 4（低风险） | — | 0 (Very Low)（极低风险） | — | — | — |
| IP-B | 3（手动）（低风险（手动）） | 25（中风险） | 0.12%（手动）（低风险（手动）） | 0.0142 (Elevated)（较高风险） | 0（手动）（低风险（手动）） | 0（手动）（低风险（手动）） | 低（手动）（低风险（手动）） |
| IP-C | 99（手动）（高风险（手动）） | 0（低风险） | 0.39%（手动）（低风险（手动）） | 0.0003 (Very Low)（极低风险） | 0（手动）（低风险（手动）） | — | 低（手动）（低风险（手动）） |
| IP-D | 3（手动）（低风险（手动）） | 11（低风险） | 2.20%（手动）（较高风险（手动）） | 0.0273 (Elevated)（较高风险） | 0（手动）（低风险（手动）） | 75（手动）（可疑IP（手动）） | — |

四、风险因子（是=阳性库数）
| IP | 代理 | Tor | VPN | 服务器 | 滥用 | 机器人 |
| IP-A | 1 | 0 | 1 | 0 | 0 | 0 |
| IP-B | 0 | 0 | 0 | 3 | 0 | 0 |
| IP-C | 1 | 0 | 3 | 2 | 0 | 0 |
| IP-D | 1 | 0 | 1 | 4 | 0 | 0 |

五、流媒体及AI解锁
| IP | TikTok | Disney+ | Netflix | YouTube | AmazonPV | Reddit | ChatGPT | Claude | Gemini |
| IP-A | 解锁 US | 解锁 | 仅自制 US | 失败 | 解锁 US | 解锁 | 解锁 US | 未知（Cloudflare 挑战） | 解锁 |
| IP-B | 解锁 | 解锁 | 解锁 | 解锁 | 解锁 | 屏蔽 | 解锁 | 未测 | 未测 |
| IP-C | 解锁 US | 解锁 US | 解锁 | 解锁 US | 解锁 US | 屏蔽 | 解锁 US | 未测 | 未测 |
| IP-D | 解锁 | 解锁 | 解锁 | 解锁 | 解锁 | 屏蔽 | 解锁 | 未测 | 未测 |

六、邮局连通性及黑名单
| IP | 本地25 | 远端25 | 有效 | 正常 | 已标记 | 黑名单 |
| IP-A | 仅 VPS 上可测 | 不可达 | 40 | 40 | 0 | 0 |
| IP-B | 阻断（手动） | 不可达（手动） | 423 | 413 | 10 | 0 |
| IP-C | 阻断（手动） | 不可达（手动） | 423 | 409 | 14 | 0 |
| IP-D | 阻断（手动） | 不可达（手动） | 423 | 403 | 18 | 2 |

建议:
  更值得留的是 IP-A（综合分 76，结论：待复核）。它的单条建议是「待复核：单源代理/VPN/Tor 标记（IPLogs: vpn/proxy），不建议直接留」。第一名仍是「待复核」，先看清风险再决定是否留下。建议换掉: IP-C（换：多源代理/VPN/Tor 阳性）、IP-D（换：多数源判机房）。因实际信号待复核: IP-A、IP-B。

```
