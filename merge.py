#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadowrocket 双配置合并器
=========================

用途：把小火箭里两份"都想要"的配置编译成一份，且冲突自动消解。

  A = 白名单过滤 + 广告过滤   （Johnshall/Shadowrocket-ADBlock-Rules-Forever，每日自动更新，3.18万 star）
  A_LEGACY = 历史 EasyList 源 （h2y/Shadowrocket-ADBlock-Rules，保留其独有的 1.3 万条 EasyList 广告规则）
  B = DNS 防泄漏              （DuskWander87/shadowrocket-config，ACL4SSR 远程规则集）
  C = 广告域名集              （Loyalsoldier/surge-rules 19.7万 + anti-AD/Johnshall 10.2万，DOMAIN-SET 索引化）

为什么不能用小火箭自带的「扩展配置 / include」：
  include 只是让 b 继承 a，不会去重也不会重排。两份配置各有一个 GEOIP 和 FINAL，
  无论谁在前都会吃掉对方 —— A 的 GEOIP 和 152 条 IP-CIDR 没有 no-resolve，会触发本地 DNS 查询，
  DNS 防泄漏当场失效。所以只能在合并阶段把顺序和参数一次性编译好。

运行：
  python3 merge.py            # 生成并校验
  python3 merge.py --check    # 只校验已有产物，不重新下载

校验不通过时不覆盖旧文件（防止上游改坏东西时把可用配置冲掉）。
"""

import argparse
import hashlib
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- 配置来源
SOURCES = {
    "A": {
        "name": "白名单过滤 + 广告过滤（Johnshall 活跃维护版）",
        "url": "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_top500_whitelist_ad.conf",
        "mirror": "https://cdn.jsdelivr.net/gh/Johnshall/Shadowrocket-ADBlock-Rules-Forever@release/sr_top500_whitelist_ad.conf",
        "fallback": "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_top500_whitelist_ad.conf",
        "min_rules": 40000,          # 低于这个数说明上游内容变了或拉取残缺
    },
    "A_LEGACY": {
        "name": "EasyList 经典广告底座（h2y 归档版）",
        "url": "https://cdn.jsdelivr.net/gh/h2y/Shadowrocket-ADBlock-Rules@master/sr_top500_whitelist_ad.conf",
        "mirror": "https://raw.githubusercontent.com/h2y/Shadowrocket-ADBlock-Rules/master/sr_top500_whitelist_ad.conf",
        "min_rules": 10000,
    },
    "B": {
        "name": "DNS 防泄漏（含 ACL4SSR 规则集）",
        "url": "https://cdn.jsdelivr.net/gh/DuskWander87/shadowrocket-config@main/shadowrocket.conf",
        "mirror": "https://raw.githubusercontent.com/DuskWander87/shadowrocket-config/main/shadowrocket.conf",
        "min_rules": 5,
    },
}

BASE = Path(__file__).resolve().parent
OUT_DIR = BASE / "out"
RULES_DIR = BASE / "rules"
MERGED = OUT_DIR / "shadowrocket.conf"
REPORT = OUT_DIR / "merge-report.txt"

# B 的规则集顺序（修复：UnBan.list、ChinaDirect.list、LocalAreaNetwork.list 必须早于广告拦截，
# 否则解禁白名单和自定义直连会被广告规则提前吃掉，沦为死代码）
B_RULESET_ORDER = [
    ("Apple.list",            10, "Apple 直连（必须早于广告拦截，否则 App Store / iCloud 被误伤）"),
    ("UnBan.list",            12, "ACL4SSR 解禁名单（必须早于广告拦截，保活腾讯视频/地震预警/群晖等）"),
    ("ChinaDirect.list",      13, "B 自建国内直连补充（必须早于广告拦截）"),
    ("LocalAreaNetwork.list", 14, "局域网直连"),
    ("Reject.list",           30, "B 自建广告拦截"),
    ("BanAD.list",            40, "ACL4SSR 广告域名"),
    ("BanProgramAD.list",     50, "ACL4SSR 程序内广告"),
    ("ChinaDomain.list",      90, "国内域名"),
    ("ChinaMedia.list",       95, "国内流媒体"),
    ("ChinaCompanyIp.list",  100, "国内企业 IP"),
    ("ChinaIp.list",         110, "国内 IP 段"),
]

# B 的 General 段：DNS 加固后的版本（比上游原版多了 DoH / proxy-dns-server，
# 去掉了不存在的 dns-fallback-system，private-ip-answer 改回 true）
GENERAL_TEMPLATE = """\
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.crashlytics.com, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32

# ---- DNS 段（B 的核心，A 的明文/旧配置已被替换）----
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, https://223.5.5.5/dns-query
proxy-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
# 保险丝：所有加密 DNS 都不通、网络全断时，把下面这行改成 system 立刻恢复
fallback-dns-server = https://1.12.12.12/dns-query

ipv6 = false
prefer-ipv6 = false
dns-direct-system = false
dns-direct-fallback-proxy = false
always-ip-address = false
private-ip-answer = true
icmp-auto-reply = true
always-reject-url-rewrite = false
udp-policy-not-supported-behaviour = REJECT
block-quic = all-proxy"""

# 强制放行的域名（优先级最高 pos 5，压过所有广告拦截）
EXEMPT = [
    # 用户 2026-11-04 明确要求：不需要放行 2345，保持 anti-AD 的拦截。
    # 如需放行任何站点，把域名加到此列表，重跑 ./publish.sh 即可 100% 生效。
]

# 百度静态资源主域（baidustatic.com）放行前的精确广告子域拦截（pos 7）
# 这样既拦截 besc/dup/ubmcmm/cpro 等百度联盟广告子域，又保证 pos 8 放行 baidustatic.com 主域静态资源
PRE_UNBREAK_REJECT = [
    "DOMAIN-SUFFIX,besc.baidustatic.com,REJECT",
    "DOMAIN-SUFFIX,dup.baidustatic.com,REJECT",
    "DOMAIN-SUFFIX,ubmcmm.baidustatic.com,REJECT",
    "DOMAIN-SUFFIX,cpro.baidustatic.com,REJECT",
    "DOMAIN-SUFFIX,pos.baidu.com,REJECT",
]

# 国内基础公共服务防误杀白名单（pos 8，早于所有广告列表）
# 原因：anti-AD 将 baidustatic.com、bootcss.com、staticfile.org 整域拉黑，
# 且将三大运营商「本机号码一键登录」认证接口及网易易盾滑块验证码列入，会导致网页静态资源及 App 一键登录失效。
UNBREAK_DIRECT = [
    # 国内三大公共静态资源 CDN 主域
    "DOMAIN-SUFFIX,baidustatic.com,DIRECT",
    "DOMAIN-SUFFIX,bootcss.com,DIRECT",
    "DOMAIN-SUFFIX,staticfile.org,DIRECT",
    "DOMAIN-SUFFIX,staticfile.net,DIRECT",
    # 网易易盾滑块验证码
    "DOMAIN,ye.dun.163yun.com,DIRECT",
    # 三大运营商本机号码一键登录认证 SDK（ACL4SSR ChinaDomain 保活项）
    "DOMAIN-SUFFIX,id6.me,DIRECT",
    "DOMAIN,auth.wosms.cn,DIRECT",
    "DOMAIN,hmrz.wo.cn,DIRECT",
    "DOMAIN,id.mail.wo.cn,DIRECT",
    "DOMAIN,mdn.open.wo.cn,DIRECT",
    "DOMAIN,opencloud.wostore.cn,DIRECT",
    "DOMAIN,config.cmpassport.com,DIRECT",
    "DOMAIN,enrichgw.10010.com,DIRECT",
    "DOMAIN,nishub1.10010.com,DIRECT",
]

# Apple 列表（pos 10）之前的 Apple 广告与崩溃分析拦截（pos 9）
# 原因：ACL4SSR Apple.list 含 DOMAIN-SUFFIX,apple.com,DIRECT，需前置拦截纯广告与图书/天气/备忘录事件上报。
# 注意：严格排除 xp.apple.com（Apple 官方列于软件更新网络要求 HT210060）及 metrics.icloud.com 等诊断接口，避免影响系统更新与诊断。
APPLE_TELEMETRY_REJECT = [
    "crashlytics.com",
    "iadsdk.apple.com",
    "api-adservices.apple.com",
    "books-analytics-events.apple.com",
    "weather-analytics-events.apple.com",
    "notes-analytics-events.apple.com",
]

# WebRTC STUN 公网 IP 探测服务器拦截（pos 9，防止 WebRTC 穿透暴露公网或节点 IP）
WEBRTC_STUN_REJECT = [
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
    "stun.cloudflare.com",
    "stun.services.mozilla.com",
    "global.stun.twilio.com",
    "stun.ekiga.net",
    "stun.ideasip.com",
    "stun.schlund.de",
    "stun.voiparound.com",
    "stun.voipbuster.com",
    "stun.voipstunt.com",
    "stun.xten.com",
    "stun.qq.com",
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.nextcloud.com",
    "stun.freeswitch.org",
    "stun.sipgate.net",
    "stun.stunprotocol.org",
    "stun.callwithus.com",
    "stun.counterpath.com",
    "stun.1und1.de",
    "stun.gmx.net",
]

# 在 UnBan.list (pos 12) 和 ChinaDirect.list (pos 13) 之前保持拦截或代理的特例（pos 11）
PRE_UNBAN_OVERRIDES = [
    "DOMAIN,dl.google.com,PROXY",
    "DOMAIN-SUFFIX,adjust.com,REJECT",
    "DOMAIN-SUFFIX,umeng.com,REJECT",
    "DOMAIN-SUFFIX,umengcloud.com,REJECT",
    "DOMAIN-SUFFIX,tracking.miui.com,REJECT",
    "DOMAIN-SUFFIX,googletraveladservices.com,REJECT",
    "DOMAIN-SUFFIX,tingyun.com,REJECT",
    "DOMAIN-SUFFIX,beizi.biz,REJECT",
]

# 额外拦截：Loyalsoldier / anti-AD 未收录的纯广告、纯事件上报端点、网页挖矿、邮件追踪像素及用户指定拦截项（pos 26）
# 兼容性边界（遵循最小误伤原则）：
# 1. 严禁整域封锁 LaunchDarkly / Split / Flagsmith / ConfigCat（其 clientstream/clientsdk/cdn 子域用于正常网页功能开关，仅封锁 events.* 纯上报子域）
# 2. 严禁封锁 app.link / bnc.lt（Branch 正常 App 深度跳转链接）及 OneTrust / CookieLaw（阻止会导致部分海外网站卡在遮罩层）
# 3. 严禁封锁 apis.google.com / t.co / redditmedia.com / vimeocdn.com / mailchimp.com 主站及前端错误 SDK 脚本主域
EXTRA_REJECT = [
    "2345.com",
    # Amazon / Google / 视频纯广告与指标上报子域
    "aax-eu.amazon.com",
    "device-metrics-us.amazon.com",
    "unagi-na.amazon.com",
    "st-widget.s3.amazonaws.com",
    "tagmanager.google.com",
    "plus.google.com",
    "pagead2.googlevideo.com",
    "bcvp0rtal.com",
    "ad.dm.gg",
    "ads.dailymotion.com",
    "video-ads.twitter.com",
    # 纯统计分析与纯事件上报子域（不封锁功能配置主域）
    "metrika.yandex.com",
    "snap.licdn.com",
    "events.launchdarkly.com",
    "events.split.io",
    # 网页加密货币挖矿（Cryptojacking）
    "coinhive-proxy.com",
    "coin-hive-proxy.com",
    "cryptoloot.org",
    "minero-proxy.com",
    "hashforcash.us",
    "fastpool.xyz",
    "minergate.com",
    "cpu.js.org",
    # OEM 系统与浏览器纯广告遥测子域
    "settings-win.data.microsoft.com",
    "ads-mas-us.vivobrowser.com",
    "ads-mas.vivobrowser.com",
    # 邮件打开率/点击追踪像素子域（保留 mailchimp.com / sendgrid.net 等主站不拦）
    "pixel.mailchimp.com",
    "open.convertkit.com",
    "customeriomail.com",
    "email-open.dripemail2.com",
    "t.sendinblue.com",
    "prox.sendinblue.com",
    "click.mailerlite.com",
    "pixel.aweber.com",
    "clicks.aweber.com",
    "open.activecampaign.com",
    "lt.activecampaign.com",
    "lt.pardot.com",
    "pi.pardot.com",
    "click.em.pardot.com",
    "email.mailgun.net",
    "track.mailgun.org",
    "track.constantcontact.com",
    "t.hubspotemail.net",
]

# 强制走代理的域名覆盖层（pos 55：位于所有广告规则 pos 20~50 之后、所有直连白名单 pos 60~90 之前）
# 包含：
# 1. Johnshall 的 top500 direct (2022) 中与 GFWList 存在主域或子域重叠的全部境外站点
# 2. ChinaDomain.list 中被墙的海外业务/港美股券商 .cn 域名（如富途、长桥、彭博、老虎、B站海外版、小米欧版等）
# 3. 开发者与常用海外生产力站点（GitHub、Steam、StackOverflow、Slack、AWS、Google、Cloudflare 等）
FORCE_PROXY = [
    # 仓库同步 / 测速 / 基础设施 / Google 边缘域名
    "github.com", "githubusercontent.com", "githubassets.com", "github.io",
    "speedtest.net", "cloudflare.com", "netlify.app", "vercel.app",
    "blog.google", "forms.gle", "storage.googleapis.com", "tools.google.com",
    # 开发者 / 游戏 / 常用工具
    "steampowered.com", "steamcommunity.com", "stackoverflow.com", "stackexchange.com",
    "slack.com", "theverge.com", "wetransfer.com", "box.com", "docker.com", "docker.io",
    "huggingface.co", "linkedin.com", "spotify.com", "imgur.com", "mega.nz",
    # Johnshall top500 direct / h2y direct 与 GFWList 交叉命中的全部域名（含被墙子域的父域）
    "9gag.com", "adobe.com", "amazon.com", "amazonaws.com", "ameblo.jp", "aol.com",
    "avg.com", "behance.net", "bet365.com", "bing.com", "canva.com", "cnbc.com",
    "cnn.com", "daum.net", "deviantart.com", "dmm.co.jp", "engadget.com", "etsy.com",
    "fandom.com", "feedly.com", "flipkart.com", "forbes.com", "foxnews.com", "ft.com",
    "godaddy.com", "goodreads.com", "hatena.ne.jp", "hola.com", "homedepot.com",
    "huffingtonpost.com", "imageshack.us", "imdb.com", "indiatimes.com", "linktr.ee",
    "list-manage.com", "live.com", "mail.ru", "mailchimp.com", "microsoft.com",
    "mit.edu", "mozilla.org", "msn.com", "namu.wiki", "nasa.gov", "naver.com",
    "naver.jp", "nicovideo.jp", "pandora.com", "pbs.org", "roblox.com",
    "rutracker.org", "standard.co.uk", "target.com", "telegraph.co.uk",
    "theguardian.com", "urbandictionary.com", "vk.com", "washingtonpost.com",
    "weebly.com", "wikia.com", "wikimedia.org", "xfinity.com", "yahoo.co.jp",
    "yahoo.com", "yandex.net", "yandex.ru", "youporn.com",
    # ChinaDomain.list / .cn 后缀中被 GFW 封锁的海外/港美股服务域名
    "bilibili.tv", "xiaomi.eu", "c.mi.com", "shortconn.im.qcloud.com", "simplecd.me",
    "666pool.cn", "bloomberg.cn", "daxa.cn", "futu.cn", "futubull.cn",
    "lightnovel.cn", "longportapp.cn", "longbridge.cn", "openapi-quote.longbridge.cn",
    "openapi-trade.longbridge.cn", "openapi.longbridge.cn", "schwab.com.cn",
    "tigerbbs.cn", "uupool.cn", "zhijianfengyi.cn", "zmw.cn",
]

TIMEOUT = 35
RETRY = 3


# ---------------------------------------------------------------- 工具函数
def fetch(url: str) -> str:
    """用 curl 拉取（本机 python 缺 CA 证书，urllib 会 SSL 校验失败）"""
    last = None
    for i in range(RETRY):
        try:
            p = subprocess.run(
                ["curl", "-sSL", "--max-time", str(TIMEOUT),
                 "-A", "sr-merge/1.2", url],
                capture_output=True, check=False,
            )
            if p.returncode == 0 and len(p.stdout) > 200:
                return p.stdout.decode("utf-8", errors="replace")
            last = f"rc={p.returncode} {p.stderr.decode(errors='replace')[:120]}"
        except Exception as e:                                    # noqa: BLE001
            last = repr(e)
        time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"拉取失败 {url}: {last}")


def fetch_with_mirror(spec: dict) -> tuple[str, str]:
    for u in (spec.get("url"), spec.get("mirror"), spec.get("fallback")):
        if not u:
            continue
        try:
            txt = fetch(u)
            if len(txt) > 200:
                return txt, u
        except Exception:                                          # noqa: BLE001
            continue
    raise RuntimeError(f"主源与镜像都失败：{spec['name']}")


def split_sections(text: str) -> dict:
    """把 conf 拆成 {段名: [行]}，段名保留大小写与空格（如 URL Rewrite）"""
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^\[(.+?)\]\s*$", line.strip())
        if m:
            cur = m.group(1).strip()
            out.setdefault(cur, [])
            continue
        if cur:
            out[cur].append(line)
    return out


def clean_lines(lines) -> list[str]:
    return [ln.rstrip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def classify(rule: str):
    """返回 (类型, 策略, url) —— 策略统一大写"""
    parts = [p.strip() for p in rule.split(",")]
    rtype = parts[0].upper()
    if rtype == "RULE-SET":
        return rtype, (
            parts[2].upper() if len(parts) > 2 else ""
        ), parts[1]
    if rtype in ("FINAL", "MATCH"):
        return rtype, parts[1].upper() if len(parts) > 1 else "", ""
    policy = parts[-1].upper() if len(parts) > 1 else ""
    if policy in {"DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
                  "URL-REGEX", "USER-AGENT", "GEOIP", "PROCESS-NAME"}:
        policy = ""
    return rtype, policy, ""


def add_no_resolve(rule: str) -> str:
    """给 IP 类规则补 no-resolve —— 这是 DNS 防泄漏的命门。"""
    parts = [p.strip() for p in rule.split(",")]
    rtype = parts[0].upper()
    if rtype not in ("IP-CIDR", "IP-CIDR6", "GEOIP"):
        return rule
    if any(p.lower() == "no-resolve" for p in parts[1:]):
        return rule
    return rule + ",no-resolve"


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def to_jsdelivr(url: str) -> str:
    """raw.githubusercontent.com -> cdn.jsdelivr.net"""
    m = re.match(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$", url)
    if not m:
        return url
    owner, repo, branch, path = m.groups()
    return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"


def normalize_rewrite(lines) -> list[str]:
    """URL Rewrite 统一处理"""
    out = []
    for ln in clean_lines(lines):
        if re.search(r"eshouhou|hzy\.pw", ln, re.I):
            continue
        ln = re.sub(r"^\^https\?://", "^http://", ln)
        out.append(ln)
    return out


# ---------------------------------------------------------------- 主流程
def build():
    log = []

    def say(msg):
        print(msg)
        log.append(msg)

    say("=" * 68)
    say(f"Shadowrocket 双配置合并   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    say("=" * 68)

    # ---- 1. 拉取 ----
    texts, urls = {}, {}
    for k, spec in SOURCES.items():
        txt, used = fetch_with_mirror(spec)
        texts[k], urls[k] = txt, used
        say(f"[拉取] {k} {spec['name']}")
        say(f"       {used}")
        say(f"       {len(txt.splitlines())} 行  sha1={hashlib.sha1(txt.encode()).hexdigest()[:12]}")

    sec_a = split_sections(texts["A"])
    sec_a_legacy = split_sections(texts["A_LEGACY"])
    sec_b = split_sections(texts["B"])

    # ---- 2. 切分 A（Johnshall）与 A_LEGACY（h2y EasyList）的规则 ----
    a_rules = clean_lines(sec_a.get("Rule", []))
    a_reject_domains = set()
    a_direct, a_proxy, a_ip, a_rulesets = [], [], [], []
    a_unknown = []

    for r in a_rules:
        rtype, policy, rurl = classify(r)
        if rtype in ("GEOIP", "FINAL", "MATCH"):
            continue                                   # 丢弃，统一由合并器重写
        if rtype == "RULE-SET":
            a_rulesets.append(f"RULE-SET,{to_jsdelivr(rurl)},{policy}")
            continue
        if rtype in ("IP-CIDR", "IP-CIDR6"):
            a_ip.append(add_no_resolve(r))
            continue
        parts = [p.strip() for p in r.split(",")]
        dom = parts[1].lower() if len(parts) > 1 else ""
        if policy in ("REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"):
            if rtype == "DOMAIN-SUFFIX" and dom:
                a_reject_domains.add(dom)
        elif policy in ("DIRECT", ""):
            a_direct.append(f"{rtype},{dom},DIRECT")
        elif policy == "PROXY":
            a_proxy.append(f"{rtype},{dom},PROXY")
        else:
            a_unknown.append(r)

    # 提取 h2y EasyList 的内联广告规则
    legacy_reject = []
    legacy_reject_domains = set()
    for r in clean_lines(sec_a_legacy.get("Rule", [])):
        rtype, policy, _ = classify(r)
        if policy in ("REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP") and rtype == "DOMAIN-SUFFIX":
            d = r.split(",")[1].strip().lower()
            legacy_reject.append(f"DOMAIN-SUFFIX,{d},REJECT")
            legacy_reject_domains.add(d)

    say(f"[拆分] A (Johnshall): Reject {len(a_reject_domains)} / Direct {len(a_direct)} / "
        f"Proxy {len(a_proxy)} / RuleSet {len(a_rulesets)} / IP {len(a_ip)} / 未识别 {len(a_unknown)}")
    say(f"[拆分] A_LEGACY (h2y EasyList): Reject {len(legacy_reject)}")

    # ---- 3. 提取 B 的 RULE-SET ----
    b_rules = clean_lines(sec_b.get("Rule", []))
    b_ruleset = {}
    for r in b_rules:
        rtype, policy, url = classify(r)
        if rtype != "RULE-SET":
            continue
        for frag, _pos, _desc in B_RULESET_ORDER:
            if frag in url:
                b_ruleset[frag] = (url, policy)
                break
    missing = [f for f, _p, _d in B_RULESET_ORDER if f not in b_ruleset]
    if missing:
        say(f"[警告] B 缺少预期规则集: {missing}")

    # ---- 4. 构建白名单保护集合，清洗广告源误杀 ----
    protected_domains = set(d.lower() for d in EXEMPT)
    for line in UNBREAK_DIRECT:
        parts = [x.strip() for x in line.split(",")]
        if len(parts) >= 2:
            protected_domains.add(parts[1].lower())

    # ---- 5. 组装 [Rule] ----
    buckets: dict[int, list[str]] = {}

    def put(pos: int, line: str):
        buckets.setdefault(pos, []).append(line)

    # pos 5: 用户自定义最高优先级放行名单
    for d in EXEMPT:
        put(5, f"DOMAIN-SUFFIX,{d},DIRECT")

    # pos 7: 百度联盟广告子域精确拦截（早于 pos 8 baidustatic.com 主域放行）
    for r in PRE_UNBREAK_REJECT:
        put(7, r)

    # pos 8: 国内公共静态资源 CDN 与运营商一键登录接口保活
    for r in UNBREAK_DIRECT:
        put(8, r)

    # pos 9: Apple 广告/隐私遥测子域拦截 + WebRTC STUN 公网探测拦截（早于 pos 10 Apple.list）
    for d in APPLE_TELEMETRY_REJECT:
        put(9, f"DOMAIN-SUFFIX,{d},REJECT")
    for d in WEBRTC_STUN_REJECT:
        put(9, f"DOMAIN-SUFFIX,{d},REJECT")

    # B 的规则集（pos 10 Apple, pos 12 UnBan, pos 13 ChinaDirect, pos 14 LAN, pos 30~50 AD, pos 90~110 CN）
    for frag, pos, _desc in B_RULESET_ORDER:
        if frag in b_ruleset:
            url, policy = b_ruleset[frag]
            put(pos, f"RULE-SET,{to_jsdelivr(url)},{policy}")

    # pos 11: 在 UnBan.list / ChinaDirect.list 之前保持拦截或代理的规则
    for r in PRE_UNBAN_OVERRIDES:
        put(11, r)

    # ---- 广告拦截：DOMAIN-SET 索引化 ----
    # 1) Loyalsoldier reject.txt (19.7 万条)
    # 2) anti-AD (10.1 万条) ∪ Johnshall (5.2 万条)，清洗掉白名单保护域名后写入 rules/anti-ad.txt
    # 注：DOMAIN-SET 本身由小火箭预处理为内存索引（O(1) 查找），不挂 pre-matching 以确保
    #     pos 5~14 的 EXEMPT / Apple / UnBan / UNBREAK_DIRECT 白名单 100% 优先生效。
    put(25, "DOMAIN-SET,https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/reject.txt,REJECT")

    anti_raw = fetch("https://anti-ad.net/surge.txt")
    anti_set = set()
    for ln in anti_raw.splitlines():
        t = ln.strip()
        if not t or t.startswith("#") or t.startswith("!"):
            continue
        q = [x.strip() for x in t.split(",")]
        if q[0].upper() == "DOMAIN-SUFFIX" and len(q) > 1:
            d = q[1].lower()
            if d not in protected_domains:
                anti_set.add(d)

    # 将 Johnshall 的 5.2 万条广告域名也并入 anti-ad.txt 索引集，确保 100% 覆盖 Johnshall 上游更新
    for d in a_reject_domains:
        if d not in protected_domains:
            anti_set.add(d)

    if len(anti_set) < 50000:
        raise RuntimeError(f"anti-AD + Johnshall 广告条数异常（{len(anti_set)}）")

    anti_domains_sorted = ["." + d for d in sorted(anti_set)]
    anti_txt_content = "\n".join(anti_domains_sorted) + "\n"
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    (RULES_DIR / "anti-ad.txt").write_text(anti_txt_content, encoding="utf-8")
    say(f"[生成] rules/anti-ad.txt  {len(anti_domains_sorted)} 条（anti-AD ∪ Johnshall，DOMAIN-SET 格式）")
    put(27, "DOMAIN-SET,https://beifang35.github.io/shadowrocket-config/rules/anti-ad.txt,REJECT")

    # pos 20: 内联广告规则（保留 h2y EasyList 规则，剔除白名单保护项）
    for r in legacy_reject:
        d = r.split(",")[1].lower()
        if d not in protected_domains:
            put(20, r)

    # pos 26: 额外拦截（Loyalsoldier 未收录但用户明确要求保持拦截的站点）
    for d in EXTRA_REJECT:
        put(26, f"DOMAIN-SUFFIX,{d},REJECT")

    # pos 55: 强制代理层（FORCE_PROXY + Johnshall 的 Proxy 列表 + AppleNews 规则集）
    # 位于所有广告拦截（pos 20~50）之后：不会放跑 ads.linkedin.com / ads.google.com 等广告子域
    # 位于所有直连白名单（pos 60~90）之前：彻底压住过时的直连判断，保证被墙域名 100% 走代理
    all_rejected = anti_set | legacy_reject_domains | set(d.lower() for d in EXTRA_REJECT) | set(d.lower() for d in APPLE_TELEMETRY_REJECT) | set(d.lower() for d in WEBRTC_STUN_REJECT)
    proxy_suffix_set = set()
    for d in FORCE_PROXY:
        dl = d.lower()
        proxy_suffix_set.add(dl)
        put(55, f"DOMAIN-SUFFIX,{dl},PROXY")

    for r in a_proxy:
        parts = [x.strip() for x in r.split(",")]
        rtype, dom = parts[0].upper(), parts[1].lower()
        # 剔除 Johnshall Proxy 列表中混入的 10 个广告统计子域（如 google-analytics / ads.google.com / amazon-adsystem）
        if dom in all_rejected or "google-analytics" in dom or "pagead" in dom or dom in ("ads.google.com", "mobileads.google.com", "afd.l.google.com"):
            continue
        if rtype == "DOMAIN-SUFFIX":
            if dom in proxy_suffix_set:
                continue
            proxy_suffix_set.add(dom)
        put(55, f"{rtype},{dom},PROXY")

    for rs in a_rulesets:
        put(55, rs)

    # pos 60: A (Johnshall) 的直连白名单（剔除已被 pos 55 代理层接管的域名，消除阴影规则）
    for r in a_direct:
        parts = [x.strip() for x in r.split(",")]
        rtype, dom = parts[0].upper(), parts[1].lower()
        if dom in proxy_suffix_set or any(dom.endswith("." + p) for p in proxy_suffix_set):
            continue
        if dom in all_rejected and dom not in protected_domains:
            continue
        put(60, f"{rtype},{dom},DIRECT")

    # pos 105: A (Johnshall) 的 152 条 IP 段（统一补 no-resolve）
    for r in a_ip:
        put(105, r)

    put(900, "GEOIP,CN,DIRECT,no-resolve")
    put(999, "FINAL,PROXY")

    rule_lines = []
    for pos in sorted(buckets):
        rule_lines.extend(buckets[pos])

    before = len(rule_lines)
    rule_lines = dedupe(rule_lines)
    say(f"[合并] 内联与规则集条目 {before} 条 -> 去重后 {len(rule_lines)} 条")

    # ---- 6. 生成文件 ----
    host_lines = clean_lines(sec_b.get("Host", [])) or ["localhost = 127.0.0.1"]
    rewrite_lines = normalize_rewrite(sec_b.get("URL Rewrite", []))

    sha_a = hashlib.sha1(texts["A"].encode()).hexdigest()[:12]
    sha_b = hashlib.sha1(texts["B"].encode()).hexdigest()[:12]
    sha_c = hashlib.sha1(anti_txt_content.encode()).hexdigest()[:12]

    body = []
    body.append("# " + "=" * 66)
    body.append("# Shadowrocket 合并配置（自动生成，勿手改）")
    body.append(f"# 上游指纹 : A={sha_a}  B={sha_b}  C={sha_c}")
    body.append("# 说明     : 上游不变则本文件逐字节不变，便于 git 判断是否需要发布")
    body.append(f"# 来源 A   : {SOURCES['A']['name']}")
    body.append(f"#            {urls['A']}")
    body.append(f"# 来源 B   : {SOURCES['B']['name']}")
    body.append(f"#            {urls['B']}")
    body.append("# 合并策略 : 放行/防误杀白名单 > Apple/UnBan/ChinaDirect > 广告拦截(内联+双DOMAIN-SET+BanAD)")
    body.append("#            > 强制代理(GFWList兜底+Johnshall Proxy) > 直连白名单 > 国内分流 > IP段(no-resolve) > GEOIP > FINAL")
    body.append("# " + "=" * 66)
    body.append("")
    body.append("[General]")
    body.extend(GENERAL_TEMPLATE.splitlines())
    body.append("")
    body.append("[Rule]")

    for pos in sorted(buckets):
        desc = next((d for _f, p, d in B_RULESET_ORDER if p == pos), None)
        label = {
            5: "放行名单（最高优先级，压过所有规则）",
            7: "百度联盟广告子域精确拦截（早于 baidustatic 主域放行）",
            8: "国内公共静态 CDN 与运营商一键登录防误杀保活",
            9: "Apple 隐私遥测拦截与 WebRTC STUN 防泄漏（早于 Apple.list）",
            11: "UnBan / ChinaDirect 前置覆盖规则",
            20: "A_LEGACY · EasyList 广告拦截（1.6 万条内联）",
            25: "广告域名集 1 · Loyalsoldier DOMAIN-SET（19.7 万条索引查找）",
            26: "额外拦截（海外广告/追踪/挖矿/遥测/邮件像素 + 2345）",
            27: "广告域名集 2 · anti-AD ∪ Johnshall DOMAIN-SET（10.8 万条索引查找，已清洗误杀）",
            55: "强制代理层（GFWList 100% 兜底 + Johnshall 代理名单）",
            60: "A · Johnshall 直连白名单（已剔除被墙与代理域名）",
            105: "A · Johnshall IP 段（152 条统一补 no-resolve）",
            900: "GeoIP 兜底（no-resolve 不可删）",
            999: "其余全部走代理",
        }.get(pos) or (f"B · {desc}" if desc else None)
        if label:
            body.append(f"# ---- {label} ----")
        body.extend(buckets[pos])
        body.append("")

    body.append("[Host]")
    body.extend(host_lines)
    body.append("")
    body.append("[URL Rewrite]")
    body.append("# 只匹配 http；https 重写需要 MITM 解密")
    body.extend(rewrite_lines or ["^http://(www\\.)?google\\.cn https://www.google.com 302"])
    body.append("")

    merged = "\n".join(body)

    # ---- 7. 校验闸门 ----
    ok = True
    say("")
    say("[校验]")

    def check(cond, msg):
        nonlocal ok
        say(("  ✓ " if cond else "  ✗ ") + msg)
        if not cond:
            ok = False

    check(len(a_reject_domains) >= 40000,
          f"A (Johnshall) 广告规则数量正常（{len(a_reject_domains)} 条）")
    check(len(legacy_reject) >= SOURCES["A_LEGACY"]["min_rules"] * 0.9,
          f"A_LEGACY (EasyList) 广告规则数量正常（{len(legacy_reject)} 条）")
    ru = [l for l in rule_lines if l.startswith("RULE-SET,")]
    check(len(ru) >= len(B_RULESET_ORDER), f"规则集齐全（{len(ru)} 个）")
    check(sum(1 for l in rule_lines if l.upper().startswith("FINAL")) == 1, "FINAL 只有一条")
    check(sum(1 for l in rule_lines if l.upper().startswith("GEOIP")) == 1, "GEOIP 只有一条")
    check("GEOIP,CN,DIRECT,no-resolve" in rule_lines, "GEOIP 带 no-resolve")
    active = [l for l in merged.splitlines() if l.strip() and not l.strip().startswith("#")]
    active_txt = "\n".join(active)
    check("dns-server = system" not in active_txt and "dns-server=system" not in active_txt,
          "没有 dns-server = system")
    check(any(l.startswith("dns-server") and "https://" in l for l in active), "DNS 走加密 DoH")
    check(any(l.startswith("proxy-dns-server") for l in active), "节点域名单独走加密 DNS")

    # 检查 UnBan.list 必须位于所有 DOMAIN-SET 与 BanAD.list 之前
    idx_unban = next((i for i, l in enumerate(rule_lines) if "UnBan.list" in l), 999999)
    idx_first_adset = next((i for i, l in enumerate(rule_lines) if l.startswith("DOMAIN-SET,") or "BanAD.list" in l), -1)
    check(idx_unban < idx_first_adset, f"UnBan.list 位于广告集之前（行 {idx_unban} < {idx_first_adset}）")

    # 检查强制代理层必须位于广告规则集之后、直连白名单之前
    idx_banprog = next((i for i, l in enumerate(rule_lines) if "BanProgramAD.list" in l), -1)
    idx_github_proxy = next((i for i, l in enumerate(rule_lines) if l == "DOMAIN-SUFFIX,github.com,PROXY"), -1)
    idx_cn_direct = next((i for i, l in enumerate(rule_lines) if l.upper() == "DOMAIN-SUFFIX,CN,DIRECT"), 999999)
    check(idx_banprog < idx_github_proxy < idx_cn_direct,
          f"强制代理层顺序正确：广告拦截({idx_banprog}) < 强制代理({idx_github_proxy}) < 直连白名单({idx_cn_direct})")

    fp = [l for l in rule_lines if l.startswith("DOMAIN-SUFFIX,") and l.endswith(",PROXY")
          and l.split(",")[1] in [d.lower() for d in FORCE_PROXY]]
    check(len(fp) == len(set(d.lower() for d in FORCE_PROXY)),
          f"强制代理覆盖层完整（{len(fp)}/{len(set(d.lower() for d in FORCE_PROXY))}）")

    ds = [l for l in rule_lines if l.startswith("DOMAIN-SET,")]
    check(len(ds) == 2, f"两个广告域名集并列（{len(ds)}/2）")
    check(any(l == "DOMAIN-SUFFIX,2345.com,REJECT" for l in rule_lines), "2345.com 保持拦截")

    raw_refs = [l for l in rule_lines
                if l.startswith(("RULE-SET,", "DOMAIN-SET,")) and "raw.githubusercontent.com" in l]
    check(not raw_refs, f"规则集全部走 jsDelivr（残留 raw 引用 {len(raw_refs)} 条）")

    nude = [l for l in rule_lines
            if re.match(r"^(IP-CIDR6?|GEOIP),", l, re.I) and "no-resolve" not in l.lower()]
    check(not nude, f"所有 IP 类规则都带 no-resolve（裸规则 {len(nude)} 条）")

    check(len(rule_lines) > 15000, f"内联规则数合理（{len(rule_lines)}）")

    say("")
    say(f"[结果] {'通过' if ok else '不通过 —— 保留旧文件，不覆盖'}")

    if ok:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        tmp = MERGED.with_suffix(".tmp")
        tmp.write_text(merged, encoding="utf-8")
        tmp.replace(MERGED)
        # 同时同步到当前目录的 shadowrocket.conf，保证 verify.py 在任何位置都能直接读取最新产物
        (BASE / "shadowrocket.conf").write_text(merged, encoding="utf-8")
        say(f"[写入] {MERGED} 与 {BASE / 'shadowrocket.conf'}  ({len(merged.encode())} 字节 / {len(body)} 行)")
    else:
        say("[保留] 校验未通过，未写入")

    report = "\n".join(log)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    if (BASE / "evidence").exists():
        (BASE / "evidence" / "最近一次构建报告.txt").write_text(report + "\n", encoding="utf-8")
    print(f"\n报告: {REPORT}")
    return 0 if ok else 1


def check_only():
    target = MERGED if MERGED.exists() else (BASE / "shadowrocket.conf")
    if not target.exists():
        print("产物不存在，先运行一次完整合并")
        return 1
    txt = target.read_text(encoding="utf-8")
    fails = []
    if "dns-server = system" in txt:
        fails.append("含 dns-server = system")
    if txt.count("\nFINAL,") != 1:
        fails.append("FINAL 数量异常")
    if "no-resolve" not in txt:
        fails.append("缺少 no-resolve")
    print("校验通过" if not fails else "校验失败: " + "; ".join(fails))
    return 0 if not fails else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只校验已有产物")
    args = ap.parse_args()
    sys.exit(check_only() if args.check else build())
