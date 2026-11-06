#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库/配置静态验收 + 验收进程发起的 DoH 探测（不证明客户端实际流量）
数据源：~/Library/Containers/com.liguangming.Shadowrocket/Data/Documents/Databases/shadowrocket.db
"""

import argparse
import ipaddress
import random
import re
import sqlite3
import sys
from pathlib import Path

from verify_support import (COMPATIBILITY_CASES, dns_checks, dns_servers,
                            fetch_text, parse_source, probe_doh, require_items,
                            secure_doh_url)

BASE = Path(__file__).resolve().parent
DB = Path.home() / "Library/Containers/com.liguangming.Shadowrocket/Data/Documents/Databases/shadowrocket.db"
CACHE = Path.home() / "Library/Containers/com.liguangming.Shadowrocket/Data/Library/Caches"

REJECT_SET = {"REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6", "GEOIP"}


def curl(url, timeout=60):
    return fetch_text(url, BASE, timeout, source_mode="remote")


def load_db():
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    rows = con.execute(
        "SELECT rowid,name,value,option,ext FROM config WHERE lower(section)='rule' ORDER BY rowid"
    ).fetchall()
    gen = {r[0]: r[1] for r in con.execute(
        "SELECT name,value FROM config WHERE lower(section)='general' ORDER BY rowid").fetchall()}
    con.close()
    return rows, gen


def load_conf_as_rows(conf_path: Path):
    rows, gen = [], {}
    mode = None
    rowid = 0
    for line in conf_path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        m = re.match(r"^\[(.+?)\]$", s)
        if m:
            mode = m.group(1)
            continue
        if not s or s.startswith("#"):
            continue
        if mode == "General" and "=" in s:
            k, v = s.split("=", 1)
            gen[k.strip()] = v.strip()
        elif mode == "Rule":
            rowid += 1
            parts = [x.strip() for x in s.split(",")]
            rtype = parts[0].upper()
            if rtype in ("FINAL", "MATCH"):
                rows.append((rowid, "FINAL", "", parts[1].upper() if len(parts) > 1 else "PROXY", ""))
            elif rtype in ("RULE-SET", "DOMAIN-SET"):
                ext = parts[3] if len(parts) > 3 else ""
                rows.append((rowid, rtype, parts[1], parts[2].upper(), ext))
            else:
                ext = ""
                for p in parts[2:]:
                    if p.lower() in ("no-resolve", "pre-matching"):
                        ext = p.lower()
                pol = parts[2].upper() if len(parts) > 2 else ""
                rows.append((rowid, rtype, parts[1] if len(parts) > 1 else "", pol, ext))
    return rows, gen


def expand(rows):
    """把 RULE-SET 与 DOMAIN-SET 展开成具体规则；真实还原 pre-matching 与 rowid 顺序"""
    out = []
    for rowid, name, value, option, ext in rows:
        if name == "COMMENT":
            continue
        is_pre = "pre-matching" in (ext or "").lower()
        if name in ("DOMAIN-SET", "RULE-SET"):
            src_name = value.split("/")[-1]
            parsed = parse_source(curl(value), name, value)
            out.extend((t, v, (option or "").upper(), nr, is_pre, src_name) for t, v, nr in parsed)
            print(f"    {name:<10} {src_name:<22} {len(parsed):>6} 条  {'[pre-matching]' if is_pre else ''}")
            continue
        nr = "no-resolve" in (ext or "").lower()
        out.append((name.upper(), value or "", (option or "").upper(), nr, is_pre, "inline"))
    return out


class M:
    def __init__(self, rules):
        # 严格还原小火箭语义：pre-matching 规则排在最前，高于一切常规规则
        ordered = [r for r in rules if r[4]] + [r for r in rules if not r[4]]
        self.exact, self.suffix, self.kw, self.ip, self.ports, self.final = {}, {}, [], [], [], None
        for i, (t, v, pol, nr, is_pre, src) in enumerate(ordered):
            if t == "DOMAIN":
                self.exact.setdefault(v.lower(), (i, pol, src))
            elif t == "DOMAIN-SUFFIX":
                self.suffix.setdefault(v.lower(), (i, pol, src))
            elif t == "DOMAIN-KEYWORD":
                self.kw.append((i, v.lower(), pol, src))
            elif t in ("DEST-PORT", "DST-PORT"):
                self.ports.append((i, v, pol))
            elif t in ("IP-CIDR", "IP-CIDR6", "GEOIP"):
                self.ip.append((i, t, v, pol, nr))
            elif t == "FINAL" and self.final is None:
                self.final = (i, pol)

    def match(self, target, port=None):
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False

        d = target.lower()
        best = None
        if not is_ip:
            if d in self.exact:
                i, pol, src = self.exact[d]
                best = (i, pol, f"DOMAIN,{d} ({src})")
            parts = d.split(".")
            for k in range(len(parts)):
                sfx = ".".join(parts[k:])
                if sfx in self.suffix:
                    i, pol, src = self.suffix[sfx]
                    if best is None or i < best[0]:
                        best = (i, pol, f"SUFFIX,{sfx} ({src})")
            for i, kword, pol, src in self.kw:
                if kword in d and (best is None or i < best[0]):
                    best = (i, pol, f"KW,{kword} ({src})")

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

        port_best = next(((i, pol, f"DEST-PORT,{v}") for i, v, pol in self.ports
                          if port is not None and v == str(port)), None)
        cands = [c for c in (best, ip_best, port_best) if c]
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
    # 防误杀保活（公共静态 CDN / 运营商一键登录 / 腾讯视频 / 地震预警）
    ("baidustatic.com", "DIRECT"), ("bootcss.com", "DIRECT"), ("staticfile.org", "DIRECT"),
    ("ye.dun.163yun.com", "DIRECT"), ("id6.me", "DIRECT"), ("auth.wosms.cn", "DIRECT"),
    ("config.cmpassport.com", "DIRECT"), ("enrichgw.10010.com", "DIRECT"),
    ("vd.l.qq.com", "DIRECT"), ("livew.l.qq.com", "DIRECT"),
    ("fairplay.l.qq.com", "DIRECT"), ("dizhensubao.getui.com", "DIRECT"),
    # 境外 —— 应代理
    ("google.com", "PROXY"), ("www.google.com", "PROXY"), ("youtube.com", "PROXY"),
    ("github.com", "PROXY"), ("githubusercontent.com", "PROXY"), ("openai.com", "PROXY"),
    ("chatgpt.com", "PROXY"), ("cursor.com", "PROXY"), ("claude.ai", "PROXY"),
    ("anthropic.com", "PROXY"), ("gemini.google.com", "PROXY"),
    ("storage.googleapis.com", "PROXY"), ("tools.google.com", "PROXY"), ("dl.google.com", "PROXY"),
    ("amazonaws.com", "PROXY"), ("s3.amazonaws.com", "PROXY"), ("amazon.com", "PROXY"),
    ("www.bing.com", "PROXY"), ("sydney.bing.com", "PROXY"), ("copilot.microsoft.com", "PROXY"),
    ("store.steampowered.com", "PROXY"), ("stackoverflow.com", "PROXY"), ("slack.com", "PROXY"),
    ("theverge.com", "PROXY"), ("wetransfer.com", "PROXY"),
    ("twitter.com", "PROXY"), ("x.com", "PROXY"), ("facebook.com", "PROXY"),
    ("instagram.com", "PROXY"), ("wikipedia.org", "PROXY"), ("netflix.com", "PROXY"),
    ("telegram.org", "PROXY"), ("cloudflare.com", "PROXY"), ("ip.sb", "PROXY"),
    ("speedtest.net", "PROXY"), ("linkedin.com", "PROXY"), ("spotify.com", "PROXY"),
    ("futu.cn", "PROXY"), ("longbridge.cn", "PROXY"), ("bloomberg.cn", "PROXY"),
    # Apple —— 应直连
    ("apple.com", "DIRECT"), ("icloud.com", "DIRECT"), ("mzstatic.com", "DIRECT"),
    ("apps.apple.com", "DIRECT"),
    *[(domain, policy) for domain, policy, _ in COMPATIBILITY_CASES],
    # 局域网
    ("192.168.1.1", "DIRECT"), ("10.0.0.1", "DIRECT"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf", action="store_true", help="直接验证本地编译后的 shadowrocket.conf")
    args = ap.parse_args()

    print("=" * 78)
    if args.conf or not DB.exists():
        conf_path = (BASE / "out" / "shadowrocket.conf") if (BASE / "out" / "shadowrocket.conf").exists() else (BASE / "shadowrocket.conf")
        print(f"二轮验收 · 数据源 = 编译产物 ({conf_path.name})")
        rows, gen = load_conf_as_rows(conf_path)
    else:
        print("二轮验收 · 数据源 = 小火箭数据库配置快照 (shadowrocket.db)")
        rows, gen = load_db()
    print("=" * 78)

    print(f"\n[读取] rule 段 {len(rows)} 行")
    print(f"[General] dns-server = {gen.get('dns-server', '?')[:90]}")
    print(f"          proxy-dns-server = {gen.get('proxy-dns-server', '(未设置)')[:60]}")
    print(f"          always-ip-address = {gen.get('always-ip-address', '?')}  "
          f"private-ip-answer = {gen.get('private-ip-answer', '?')}")

    print(f"\n[展开 RULE-SET / DOMAIN-SET]")
    try:
        rules = require_items(expand(rows), "规则链")
    except Exception as e:
        print(f"规则集验收失败: {e}")
        return 1
    print(f"[规则链] 展开后 {len(rules)} 条")

    m = M(rules)
    fails = []

    # ---------- 1. 白名单 / 分流 ----------
    print("\n" + "-" * 78)
    print(f"① 白名单与代理分流测试（{len(WHITE)} 项核心流量）")
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

    # 提取前置白名单（Apple.list / UnBan.list / ChinaDirect.list / UNBREAK_DIRECT）豁免后缀，
    # 抽样时区分「设计内的前置白名单豁免」与「真正的漏拦」
    exempt_exact, exempt_sfx = set(), set()
    for t, v, pol, _nr, _pre, src in rules:
        if src in ("reject.txt", "anti-ad.txt"):
            break
        if pol == "DIRECT":
            if t == "DOMAIN":
                exempt_exact.add(v.lower())
            elif t == "DOMAIN-SUFFIX":
                exempt_sfx.add(v.lower())

    def is_exempted_by_whitelist(dom: str) -> bool:
        d = dom.lower()
        if d in exempt_exact:
            return True
        parts = d.split(".")
        return any(".".join(parts[i:]) in exempt_sfx for i in range(len(parts)))

    def sample_from(url, n=600):
        out = []
        for _kind, dom, _nr in parse_source(curl(url), "DOMAIN-SET", url):
            if not is_exempted_by_whitelist(dom):
                out.append(dom)
        require_items(out, f"{url} 广告抽样（剔除白名单后）")
        return random.sample(out, min(n, len(out)))

    sampled = 0
    for name, url in [
        ("Loyalsoldier", "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/reject.txt"),
        ("anti-AD∪Johnshall", "https://beifang35.github.io/shadowrocket-config/rules/anti-ad.txt"),
    ]:
        try:
            sample = sample_from(url, 600)
        except Exception as e:                                # noqa: BLE001
            print(f"  {name} 抽检失败：{e}")
            fails.append(("广告取样", url, "有效非空样本", str(e), name))
            continue
        sampled += len(sample)
        miss = [d for d in sample if m.match(d)[0] not in REJECT_SET]
        print(f"  {name:<18} 抽检 {len(sample)} 条 → 未拦截 {len(miss)} 条", end="")
        print("  ✓" if not miss else "  ✗")
        for d in miss[:8]:
            pol, rule, _ = m.match(d)
            print(f"      {d:<34} {pol:<8} {rule}")
            fails.append(("广告", d, "REJECT", pol, rule))

    # 已知经典广告域名（含之前漏拦的 ads.linkedin.com / ads.google.com / 百度联盟子域 / 2345）
    classic = [
        "doubleclick.net", "google-analytics.com", "googlesyndication.com",
        "ads.google.com", "pagead.google.com", "amazon-adsystem.com", "ads.linkedin.com",
        "umeng.com", "cnzz.com", "popads.net", "adjust.com", "app.adjust.com",
        "adservice.google.com", "pglstatp-toutiao.com", "xdcs-collector.ximalaya.com",
        "besc.baidustatic.com", "dup.baidustatic.com", "2345.com",
        "iadsdk.apple.com", "api-adservices.apple.com", "events.launchdarkly.com",
        "stun.l.google.com", "stun.cloudflare.com", "aax-eu.amazon.com",
        "pagead2.googlevideo.com", "coinhive-proxy.com", "pixel.mailchimp.com",
    ]
    bad = [d for d in classic if m.match(d)[0] not in REJECT_SET]
    print(f"  经典广告域名 {len(classic)} 条 → 未拦截 {len(bad)} 条", end="")
    print("  ✓" if not bad else "  ✗")
    for d in bad:
        pol, rule, _ = m.match(d)
        print(f"      {d:<34} {pol:<8} {rule}")
        fails.append(("广告", d, "REJECT", pol, rule))

    # ---------- 3. DNS 防泄漏配置检查与 DoH 实时探测 ----------
    print("\n" + "-" * 78)
    print("③ DNS 防泄漏配置检查与 DoH 实时连通性探测（静态规则 + RFC 8484 Wire 探测）")
    print("-" * 78)
    ip_rules = [r for r in rules if r[0] in IP_TYPES]
    nude = [r for r in ip_rules if not r[3]]
    print(f"  IP 类规则 {len(ip_rules)} 条，带 no-resolve {len(ip_rules)-len(nude)} 条", end="")
    print("  ✓" if not nude else "  ✗")
    for r in nude[:5]:
        print(f"      裸规则: {r[0]},{r[1]},{r[2]}")
    if nude:
        fails.append(("DNS", "IP规则no-resolve", "0裸规则", f"{len(nude)}条裸规则", str(nude[0][:3])))

    geo = [r for r in rules if r[0] == "GEOIP"]
    geo_ok = bool(geo) and all(g[3] for g in geo)
    print(f"  GEOIP 规则 {len(geo)} 条，带 no-resolve {sum(1 for g in geo if g[3])} 条", end="")
    print("  ✓" if geo_ok else "  ✗")
    if not geo_ok:
        fails.append(("DNS", "GEOIP带no-resolve", "True", str(geo_ok), "GEOIP"))

    leak = [(d, m.match(d)[2]) for d, _ in WHITE if m.match(d)[2] > 0]
    print(f"  {len(WHITE)} 条流量静态匹配过程中触发 IP 规则解析: {len(leak)} 次", end="")
    print("  ✓" if not leak else "  ✗")
    for d, n in leak:
        print(f"      {d} 触发 {n} 次")
        fails.append(("DNS", d, "0次解析", f"{n}次解析", "静态模拟"))

    for ok, description in dns_checks(gen):
        print(f"  {description}: {'✓' if ok else '✗'}")
        if not ok:
            fails.append(("DNS", description, "通过", "失败", "General"))
    for server in ("223.5.5.5", "119.29.29.29", "8.8.8.8"):
        pol, rule, _ = m.match(server, port=53)
        ok = pol == "PROXY"
        print(f"  DNS 端口静态匹配 {server}:53 → {pol} {'✓' if ok else '✗'}")
        if not ok:
            fails.append(("DNS", server + ":53", "PROXY", pol, rule))

    always_ip_ok = gen.get("always-ip-address") == "false"
    print(f"  always-ip-address: {gen.get('always-ip-address')} "
          f"{'✓（未强制本地解析）' if always_ip_ok else '✗'}")
    if not always_ip_ok:
        fails.append(("DNS", "always-ip-address", "false", str(gen.get("always-ip-address")), "General"))

    priv_ip_ok = gen.get("private-ip-answer") == "true"
    print(f"  private-ip-answer: {gen.get('private-ip-answer')} {'✓' if priv_ip_ok else '✗'}")
    if not priv_ip_ok:
        fails.append(("DNS", "private-ip-answer", "true", str(gen.get("private-ip-answer")), "General"))

    # 探测主/节点域名/回退 DNS 的所有唯一 HTTPS 端点，保留并解析完整响应。
    all_doh = list(dict.fromkeys(u for urls in dns_servers(gen).values()
                                for u in urls if secure_doh_url(u)))
    for u in all_doh:
        try:
            out_str = probe_doh(u)
            ok_doh = True
        except Exception as e:
            out_str, ok_doh = str(e), False
        print(f"  DoH 实时探测 {u:<38} -> {out_str or 'ERR'} {'✓' if ok_doh else '✗'}")
        if not ok_doh:
            fails.append(("DoH探测", u, "HTTP200 + DNS报文有效 + 目标解析成功", out_str, "RFC8484"))

    # ---------- 汇总 ----------
    print("\n" + "=" * 78)
    if fails:
        print(f"存在问题 ❌  {len(fails)} 项失败")
        for cat, d, exp, act, rule in fails:
            print(f"  [{cat}] {d:<30} 期望 {exp} 实际 {act}  ({rule})")
        return 1
    print("二轮验收全部通过 ✅")
    print(f"  静态白名单/分流 {len(WHITE)}/{len(WHITE)} · 广告抽检 {sampled}+{len(classic)} 条全拦截 · DNS配置与探测通过")
    print("  本结果不证明 Shadowrocket 实际 DNS 出口、浏览器指纹或 WebRTC 泄漏；这些需独立流量/浏览器验收。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
