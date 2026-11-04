#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadowrocket 双配置合并器
=========================

用途：把小火箭里两份"都想要"的配置编译成一份，且冲突自动消解。

  A = 白名单过滤 + 广告过滤   （h2y/Shadowrocket-ADBlock-Rules，1.6 万条内联规则）
  B = DNS 防泄漏              （DuskWander87/shadowrocket-config，ACL4SSR 远程规则集）

合并后同时得到：A 的 16254 条广告拦截 + A 的 337 条直连白名单，以及 B 的加密 DNS 和国内分流。

为什么不能用小火箭自带的「扩展配置 / include」：
  include 只是让 b 继承 a，不会去重也不会重排。两份配置各有一个 GEOIP 和 FINAL，
  无论谁在前都会吃掉对方 —— A 的 GEOIP 没有 no-resolve，会触发本地 DNS 查询，
  DNS 防泄漏当场失效。所以只能在合并阶段把顺序和参数一次性编译好。

运行：
  python3 merge.py            # 生成并校验
  python3 merge.py --check    # 只校验已有产物，不重新下载

校验不通过时不覆盖旧文件（防止上游改坏东西时把可用配置冲掉）。
"""

import argparse
import hashlib
import re
import sys
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- 配置来源
SOURCES = {
    "A": {
        "name": "白名单过滤 + 广告过滤",
        "url": "https://raw.githubusercontent.com/h2y/Shadowrocket-ADBlock-Rules/master/sr_top500_whitelist_ad.conf",
        "mirror": "https://cdn.jsdelivr.net/gh/h2y/Shadowrocket-ADBlock-Rules@master/sr_top500_whitelist_ad.conf",
        "min_rules": 10000,          # 低于这个数说明上游内容变了或拉取残缺
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
MERGED = OUT_DIR / "shadowrocket.conf"
REPORT = OUT_DIR / "merge-report.txt"

# A 的广告规则多，B 的规则集少但覆盖全 —— 这个顺序是合并策略的核心，不要随手改
# key = B 配置里的 RULE-SET 文件名片段，value = 在合并结果里的插入位置编号
B_RULESET_ORDER = [
    ("Apple.list",            10, "Apple 直连（必须早于广告拦截，否则 App Store / iCloud 被误伤）"),
    ("Reject.list",           30, "B 自建广告拦截"),
    ("BanAD.list",            40, "ACL4SSR 广告域名"),
    ("BanProgramAD.list",     50, "ACL4SSR 程序内广告"),
    ("ChinaDirect.list",      70, "B 自建国内直连补充"),
    ("LocalAreaNetwork.list", 80, "局域网直连"),
    ("UnBan.list",            85, "解禁名单"),
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

# ---- DNS 段（B 的核心，A 的 dns-server = system 已被替换）----
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

# 强制走代理的域名
# ---------------------------------------------------------------
# A 的 2021 年白名单把下面这些判成「境外可直连」，但这个判断已经过时：
# 交叉 GFWList（4062 条被墙域名）后发现 37 个命中 —— 按 A 的原样走直连会打不开。
# 另外 github 系影响本机 obsidian vault 的 git 同步，speedtest 影响测速准确性。
#
# 覆盖层插在 A 的 Direct 白名单之前（pos 15），所以能压住 A 的判断。
# 代价：个别其实能直连的站点会绕一次代理，稍慢；收益：不会出现「点了打不开」。
#
# 想关掉某一项：从下面删掉那一行，重跑 ./publish.sh。
FORCE_PROXY = [
    # 仓库同步 / 测速准确性（不在 GFWList 里，但直连不可靠）
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "github.io",
    "speedtest.net",
    # A 判直连、GFWList 判被墙（2026-11 交叉比对结果）
    "9gag.com", "ameblo.jp", "avg.com", "behance.net", "bet365.com",
    "canva.com", "daum.net", "deviantart.com", "dmm.co.jp", "etsy.com",
    "feedly.com", "flipkart.com", "forbes.com", "godaddy.com", "goodreads.com",
    "hola.com", "homedepot.com", "huffingtonpost.com", "imgur.com",
    "linkedin.com", "mega.nz", "namu.wiki", "naver.com", "nicovideo.jp",
    "pandora.com", "roblox.com", "rutracker.org", "spotify.com",
    "theguardian.com", "washingtonpost.com", "weebly.com", "wikimedia.org",
    "xfinity.com", "yahoo.com", "youporn.com",
]

TIMEOUT = 30
RETRY = 3


# ---------------------------------------------------------------- 工具函数
def fetch(url: str) -> str:
    """用 curl 拉取（本机 python 缺 CA 证书，urllib 会 SSL 校验失败）"""
    last = None
    for i in range(RETRY):
        try:
            p = subprocess.run(
                ["curl", "-sSL", "--max-time", str(TIMEOUT),
                 "-A", "sr-merge/1.0", url],
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
    for u in (spec["url"], spec.get("mirror")):
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
    """返回 (类型, 策略) —— 策略统一大写"""
    parts = [p.strip() for p in rule.split(",")]
    rtype = parts[0].upper()
    if rtype == "RULE-SET":
        return rtype, (
            parts[2].upper() if len(parts) > 2 else ""
        ), parts[1]
    if rtype in ("FINAL", "MATCH"):
        return rtype, parts[1].upper() if len(parts) > 1 else "", ""
    policy = parts[-1].upper() if len(parts) > 1 else ""
    # 两段式规则（如 ACL4SSR 列表里的 DOMAIN-SUFFIX,x）没有策略
    if policy in {"DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
                  "URL-REGEX", "USER-AGENT", "GEOIP", "PROCESS-NAME"}:
        policy = ""
    return rtype, policy, ""


def add_no_resolve(rule: str) -> str:
    """给 IP 类规则补 no-resolve —— 这是 DNS 防泄漏的命门。
    不补：每个域名请求都要本地解析一次才能判断是否命中，等于全量暴露。"""
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
    """raw.githubusercontent.com -> cdn.jsdelivr.net
    国内直连 raw 经常超时；规则集拉不下来的话小火箭会退化成「全部走代理」。
    这不是可选项，是可用性前提。"""
    m = re.match(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$", url)
    if not m:
        return url
    owner, repo, branch, path = m.groups()
    return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"


def normalize_rewrite(lines) -> list[str]:
    """URL Rewrite 统一处理：
    - 强制降到 http 匹配（https 的重写要开 MITM 解密才生效，写了也是误导）
    - 剔除 B 作者个人业务域名（eshouhou 等），对别人无意义
    """
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
    sec_b = split_sections(texts["B"])

    # ---- 2. 切分 A 的规则 ----
    a_rules = clean_lines(sec_a.get("Rule", []))
    a_reject, a_direct, a_proxy, a_ip = [], [], [], []
    a_unknown = []
    for r in a_rules:
        rtype, policy, _ = classify(r)
        if rtype in ("GEOIP", "FINAL", "MATCH"):
            continue                                   # 丢弃，统一由合并器重写
        if rtype in ("IP-CIDR", "IP-CIDR6"):
            a_ip.append(add_no_resolve(r))
            continue
        if policy in ("REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"):
            a_reject.append(r)
        elif policy in ("DIRECT", ""):
            a_direct.append(r)
        elif policy == "PROXY":
            a_proxy.append(r)
        else:
            a_unknown.append(r)

    say(f"[拆分] A: Reject {len(a_reject)} / Direct {len(a_direct)} / "
        f"Proxy {len(a_proxy)} / IP {len(a_ip)} / 未识别 {len(a_unknown)}")
    if a_unknown:
        say(f"       未识别样例: {a_unknown[:3]}")

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

    # ---- 4. 组装 [Rule] ----
    buckets: dict[int, list[str]] = {}

    def put(pos: int, line: str):
        buckets.setdefault(pos, []).append(line)

    for frag, pos, _desc in B_RULESET_ORDER:
        if frag in b_ruleset:
            url, policy = b_ruleset[frag]
            put(pos, f"RULE-SET,{to_jsdelivr(url)},{policy}")

    for r in a_reject:
        put(20, r)          # A 的 1.6 万条广告，紧跟 Apple 直连之后
    for r in a_direct:
        put(60, r)
    for r in a_proxy:
        put(65, r)
    for r in a_ip:
        put(105, r)         # A 的 IP 段放最后（域名请求因 no-resolve 会跳过）

    # 强制代理覆盖层：A 是 2021 年的"境外可直连"白名单，这些站点当年能直连、
    # 现在不行了。必须插在 A 的 Direct 白名单（pos 60）之前，否则永远轮不到它。
    for d in FORCE_PROXY:
        put(15, f"DOMAIN-SUFFIX,{d},PROXY")

    put(900, "GEOIP,CN,DIRECT,no-resolve")
    put(999, "FINAL,PROXY")

    rule_lines = []
    for pos in sorted(buckets):
        rule_lines.extend(buckets[pos])

    before = len(rule_lines)
    rule_lines = dedupe(rule_lines)
    say(f"[合并] 规则 {before} 条 -> 去重后 {len(rule_lines)} 条")

    # ---- 5. 生成文件 ----
    host_lines = clean_lines(sec_b.get("Host", [])) or ["localhost = 127.0.0.1"]
    rewrite_lines = normalize_rewrite(sec_b.get("URL Rewrite", []))

    body = []
    body.append("# " + "=" * 66)
    body.append("# Shadowrocket 合并配置（自动生成，勿手改）")
    body.append(f"# 上游指纹 : A={hashlib.sha1(texts['A'].encode()).hexdigest()[:12]}"
                f"  B={hashlib.sha1(texts['B'].encode()).hexdigest()[:12]}")
    body.append("# 说明     : 上游不变则本文件逐字节不变，便于 git 判断是否需要发布")
    body.append(f"# 来源 A   : {SOURCES['A']['name']}")
    body.append(f"#            {urls['A']}")
    body.append(f"# 来源 B   : {SOURCES['B']['name']}")
    body.append(f"#            {urls['B']}")
    body.append("# 合并策略 : Apple直连 > A广告拦截 > B广告拦截 > A直连白名单 > A代理白名单")
    body.append("#            > B国内分流 > A的IP段 > GEOIP(no-resolve) > FINAL")
    body.append("# " + "=" * 66)
    body.append("")
    body.append("[General]")
    body.extend(GENERAL_TEMPLATE.splitlines())
    body.append("")
    body.append("[Rule]")

    for pos in sorted(buckets):
        desc = next((d for _f, p, d in B_RULESET_ORDER if p == pos), None)
        label = {
            20: "A 的广告拦截（EasyList 系，1.6 万条）",
            60: "A 的直连白名单",
            65: "A 的强制代理名单",
            15: "强制代理覆盖层（A 的白名单里已过时的境外站点）",
            105: "A 的 IP 段（统一补 no-resolve）",
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

    # ---- 6. 校验闸门 ----
    ok = True
    say("")
    say("[校验]")

    def check(cond, msg):
        nonlocal ok
        say(("  ✓ " if cond else "  ✗ ") + msg)
        if not cond:
            ok = False

    check(len(a_reject) >= SOURCES["A"]["min_rules"] * 0.9,
          f"A 的广告规则数量正常（{len(a_reject)} 条）")
    ru = [l for l in rule_lines if l.startswith("RULE-SET,")]
    check(len(ru) >= len(B_RULESET_ORDER) - 1, f"B 的规则集齐全（{len(ru)}/{len(B_RULESET_ORDER)}）")
    check(sum(1 for l in rule_lines if l.upper().startswith("FINAL")) == 1, "FINAL 只有一条")
    check(sum(1 for l in rule_lines if l.upper().startswith("GEOIP")) == 1, "GEOIP 只有一条")
    check("GEOIP,CN,DIRECT,no-resolve" in rule_lines, "GEOIP 带 no-resolve")
    active = [l for l in merged.splitlines() if l.strip() and not l.strip().startswith("#")]
    active_txt = "\n".join(active)
    check("dns-server = system" not in active_txt and "dns-server=system" not in active_txt,
          "没有 dns-server = system")
    check(any(l.startswith("dns-server") and "https://" in l for l in active), "DNS 走加密 DoH")
    check(any(l.startswith("proxy-dns-server") for l in active), "节点域名单独走加密 DNS")

    fp = [l for l in rule_lines if l.startswith("DOMAIN-SUFFIX,") and l.endswith(",PROXY")
          and l.split(",")[1] in FORCE_PROXY]
    check(len(fp) == len(FORCE_PROXY), f"强制代理覆盖层完整（{len(fp)}/{len(FORCE_PROXY)}）")

    raw_refs = [l for l in rule_lines if "raw.githubusercontent.com" in l]
    check(not raw_refs, f"规则集全部走 jsDelivr（残留 raw 引用 {len(raw_refs)} 条）")

    nude = [l for l in rule_lines
            if re.match(r"^(IP-CIDR6?|GEOIP),", l, re.I) and "no-resolve" not in l.lower()]
    check(not nude, f"所有 IP 类规则都带 no-resolve（裸规则 {len(nude)} 条）")

    check(len(rule_lines) > 10000, f"总规则数合理（{len(rule_lines)}）")

    say("")
    say(f"[结果] {'通过' if ok else '不通过 —— 保留旧文件，不覆盖'}")

    if ok:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        tmp = MERGED.with_suffix(".tmp")
        tmp.write_text(merged, encoding="utf-8")
        tmp.replace(MERGED)
        say(f"[写入] {MERGED}  ({len(merged.encode())} 字节 / {len(body)} 行)")
    else:
        say("[保留] 校验未通过，未写入")

    report = "\n".join(log)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(f"\n报告: {REPORT}")
    return 0 if ok else 1


def check_only():
    if not MERGED.exists():
        print("产物不存在，先运行一次完整合并")
        return 1
    txt = MERGED.read_text(encoding="utf-8")
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
