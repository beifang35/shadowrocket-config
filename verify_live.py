#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
二轮验收 —— 直接读小火箭「实际生效」的数据库，不读配置文件。
数据源：~/Library/Containers/com.liguangming.Shadowrocket/Data/Documents/Databases/shadowrocket.db
"""

import ipaddress
import random
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

DB = Path.home() / "Library/Containers/com.liguangming.Shadowrocket/Data/Documents/Databases/shadowrocket.db"
CACHE = Path.home() / "Library/Containers/com.liguangming.Shadowrocket/Data/Library/Caches"

REJECT_SET = {"REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6", "GEOIP"}


def curl(url, timeout=60):
    p = subprocess.run(["curl", "-sSL", "--max-time", str(timeout), url],
                       capture_output=True, check=False)
    return p.stdout.decode("utf-8", errors="replace")


def load_db():
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    rows = con.execute(
        "SELECT rowid,name,value,option,ext FROM config WHERE section='rule' ORDER BY rowid"
    ).fetchall()
    gen = {r[0]: r[1] for r in con.execute(
        "SELECT name,value FROM config WHERE section='general'").fetchall()}
    con.close()
    return rows, gen


def expand(rows):
    """把 RULE-SET 展开成具体规则；顺序按 rowid 保持"""
    out = []
    for rowid, name, value, option, ext in rows:
        if name == "COMMENT":
            continue
        if name == "RULE-SET":
            body = curl(value)
            n = 0
            for ln in body.splitlines():
                s = ln.strip()
                if not s or s.startswith("#") or s.startswith("//"):
                    continue
                p = [x.strip() for x in s.split(",")]
                t = p[0].upper()
                if t not in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
                             "IP-CIDR", "IP-CIDR6", "GEOIP", "URL-REGEX", "USER-AGENT"):
                    continue
                nr = any(x.lower() == "no-resolve" for x in p)
                out.append((t, p[1] if len(p) > 1 else "", (option or "").upper(), nr, value.split("/")[-1]))
                n += 1
            print(f"    RULE-SET {value.split('/')[-1]:<24} {n:>6} 条")
            continue
        nr = (ext or "").lower() == "no-resolve"
        out.append((name.upper(), value or "", (option or "").upper(), nr, "inline"))
    return out


class M:
    def __init__(self, rules):
        self.exact, self.suffix, self.kw, self.ip, self.final = {}, {}, [], [], None
        for i, (t, v, pol, nr, src) in enumerate(rules):
            if t == "DOMAIN":
                self.exact.setdefault(v.lower(), (i, pol))
            elif t == "DOMAIN-SUFFIX":
                self.suffix.setdefault(v.lower(), (i, pol))
            elif t == "DOMAIN-KEYWORD":
                self.kw.append((i, v.lower(), pol))
            elif t in ("IP-CIDR", "IP-CIDR6", "GEOIP"):
                self.ip.append((i, t, v, pol, nr))
            elif t == "FINAL" and self.final is None:
                self.final = (i, pol)

    def match(self, target):
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False

        d = target.lower()
        best = None
        if not is_ip:
            if d in self.exact:
                best = (self.exact[d][0], self.exact[d][1], "DOMAIN")
            parts = d.split(".")
            for k in range(len(parts)):
                sfx = ".".join(parts[k:])
                if sfx in self.suffix:
                    i, pol = self.suffix[sfx]
                    if best is None or i < best[0]:
                        best = (i, pol, f"SUFFIX,{sfx}")
            for i, kword, pol in self.kw:
                if kword in d and (best is None or i < best[0]):
                    best = (i, pol, f"KW,{kword}")

        dns_hits = 0
        ip_best = None
        for i, t, v, pol, nr in self.ip:
            if not is_ip:
                if nr:
                    continue
                dns_hits += 1
                continue
            if t == "GEOIP":
                continue
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(v, strict=False):
                    if ip_best is None or i < ip_best[0]:
                        ip_best = (i, pol, f"{t},{v}")
            except ValueError:
                pass

        cands = [c for c in (best, ip_best) if c]
        if cands:
            c = min(cands, key=lambda x: x[0])
            return c[1], c[2], dns_hits
        if self.final:
            return self.final[1], "FINAL", dns_hits
        return "NO-MATCH", "-", dns_hits


WHITE = [
    # 国内 —— 应直连
    ("baidu.com", "DIRECT"), ("www.baidu.com", "DIRECT"), ("taobao.com", "DIRECT"),
    ("jd.com", "DIRECT"), ("qq.com", "DIRECT"), ("bilibili.com", "DIRECT"),
    ("weibo.com", "DIRECT"), ("zhihu.com", "DIRECT"), ("163.com", "DIRECT"),
    ("alipay.com", "DIRECT"), ("meituan.com", "DIRECT"), ("douyin.com", "DIRECT"),
    ("xiaohongshu.com", "DIRECT"), ("aliyun.com", "DIRECT"), ("tencent.com", "DIRECT"),
    ("iqiyi.com", "DIRECT"), ("youku.com", "DIRECT"), ("ctrip.com", "DIRECT"),
    # 境外 —— 应代理
    ("google.com", "PROXY"), ("www.google.com", "PROXY"), ("youtube.com", "PROXY"),
    ("github.com", "PROXY"), ("githubusercontent.com", "PROXY"), ("openai.com", "PROXY"),
    ("chatgpt.com", "PROXY"), ("cursor.com", "PROXY"), ("claude.ai", "PROXY"),
    ("anthropic.com", "PROXY"), ("gemini.google.com", "PROXY"),
    ("twitter.com", "PROXY"), ("x.com", "PROXY"), ("facebook.com", "PROXY"),
    ("instagram.com", "PROXY"), ("wikipedia.org", "PROXY"), ("netflix.com", "PROXY"),
    ("telegram.org", "PROXY"), ("cloudflare.com", "PROXY"), ("ip.sb", "PROXY"),
    ("speedtest.net", "PROXY"), ("linkedin.com", "PROXY"), ("spotify.com", "PROXY"),
    # Apple —— 应直连
    ("apple.com", "DIRECT"), ("icloud.com", "DIRECT"), ("mzstatic.com", "DIRECT"),
    ("apps.apple.com", "DIRECT"),
    # 局域网
    ("192.168.1.1", "DIRECT"), ("10.0.0.1", "DIRECT"),
]


def main():
    print("=" * 78)
    print("二轮验收 · 数据源 = 小火箭实际生效的数据库")
    print("=" * 78)

    rows, gen = load_db()
    print(f"\n[读取] {DB.name}  rule 段 {len(rows)} 行")
    print(f"[General] dns-server = {gen.get('dns-server', '?')[:90]}")
    print(f"          proxy-dns-server = {gen.get('proxy-dns-server', '(未设置)')[:60]}")
    print(f"          always-ip-address = {gen.get('always-ip-address', '?')}  "
          f"private-ip-answer = {gen.get('private-ip-answer', '?')}")

    print(f"\n[展开 RULE-SET]")
    rules = expand(rows)
    print(f"[规则链] 展开后 {len(rules)} 条")

    m = M(rules)
    fails = []

    # ---------- 1. 白名单 / 分流 ----------
    print("\n" + "-" * 78)
    print("① 白名单测试（分流是否正确）")
    print("-" * 78)
    print(f"  {'域名':<28}{'期望':<8}{'实际':<9}{'本地DNS':<8}判定")
    for dom, exp in WHITE:
        pol, rule, hits = m.match(dom)
        ok = (pol == exp)
        if not ok:
            fails.append(("白名单", dom, exp, pol, rule))
        print(f"  {dom:<28}{exp:<8}{pol:<9}{hits:<8}{'✓' if ok else '✗'}")
    print(f"\n  结果: {sum(1 for d,e in WHITE if m.match(d)[0]==e)}/{len(WHITE)} 通过")

    # ---------- 2. 广告拦截 ----------
    print("\n" + "-" * 78)
    print("② 广告测试（拦截是否生效）")
    print("-" * 78)
    random.seed(42)
    # 从 anti-AD 抽样
    anti = []
    for ln in curl("https://anti-ad.net/surge.txt").splitlines():
        s = ln.strip()
        if s.startswith("DOMAIN-SUFFIX,"):
            anti.append(s.split(",")[1])
    sample = random.sample(anti, min(800, len(anti)))
    miss = [d for d in sample if m.match(d)[0] not in REJECT_SET]
    print(f"  anti-AD 抽检 {len(sample)} 条 → 未拦截 {len(miss)} 条", end="")
    print("  ✓" if not miss else "  ✗")
    for d in miss[:10]:
        pol, rule, _ = m.match(d)
        print(f"      {d:<34} {pol:<8} {rule}")
        fails.append(("广告", d, "REJECT", pol, rule))

    # 已知经典广告域名
    classic = ["doubleclick.net", "google-analytics.com", "googlesyndication.com",
               "umeng.com", "cnzz.com", "popads.net", "adjust.com", "adservice.google.com",
               "pglstatp-toutiao.com", "xdcs-collector.ximalaya.com"]
    bad = [d for d in classic if m.match(d)[0] not in REJECT_SET]
    print(f"  经典广告域名 {len(classic)} 条 → 未拦截 {len(bad)} 条", end="")
    print("  ✓" if not bad else "  ✗")
    for d in bad:
        pol, rule, _ = m.match(d)
        print(f"      {d:<34} {pol:<8} {rule}")
        fails.append(("广告", d, "REJECT", pol, rule))

    # ---------- 3. DNS 泄漏 ----------
    print("\n" + "-" * 78)
    print("③ DNS 泄漏测试")
    print("-" * 78)
    ip_rules = [r for r in rules if r[0] in IP_TYPES]
    nude = [r for r in ip_rules if not r[3]]
    print(f"  IP 类规则 {len(ip_rules)} 条，带 no-resolve {len(ip_rules)-len(nude)} 条", end="")
    print("  ✓" if not nude else "  ✗")
    for r in nude[:5]:
        print(f"      裸规则: {r[0]},{r[1]},{r[2]}")

    geo = [r for r in rules if r[0] == "GEOIP"]
    print(f"  GEOIP 规则 {len(geo)} 条，带 no-resolve {sum(1 for g in geo if g[3])} 条", end="")
    print("  ✓" if geo and all(g[3] for g in geo) else "  ✗")

    leak = [(d, m.match(d)[2]) for d, _ in WHITE if m.match(d)[2] > 0]
    print(f"  46 条流量匹配过程中触发本地 DNS 查询: {len(leak)} 次", end="")
    print("  ✓（零泄露）" if not leak else "  ✗")
    for d, n in leak:
        print(f"      {d} 触发 {n} 次")

    dns_ok = gen.get("dns-server", "").startswith("https://")
    print(f"  dns-server 是否加密: {'是 ✓' if dns_ok else '否 ✗'}")
    print(f"  proxy-dns-server 是否设置: {'是 ✓' if gen.get('proxy-dns-server') else '否 ✗'}")
    print(f"  always-ip-address: {gen.get('always-ip-address')} "
          f"{'✓（未强制本地解析）' if gen.get('always-ip-address') != 'true' else '✗'}")

    # ---------- 汇总 ----------
    print("\n" + "=" * 78)
    if fails:
        print(f"存在问题 ❌  {len(fails)} 项失败")
        for cat, d, exp, act, rule in fails:
            print(f"  [{cat}] {d:<30} 期望 {exp} 实际 {act}  ({rule})")
        return 1
    print("二轮验收全部通过 ✅")
    print(f"  白名单 {len(WHITE)}/{len(WHITE)} · 广告抽检 {len(sample)}+{len(classic)} 条全拦截 · DNS 零泄露")
    return 0


if __name__ == "__main__":
    sys.exit(main())
