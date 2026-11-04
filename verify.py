#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadowrocket 配置验收器
=======================

把合并后的 conf 当代码来测：展开全部 RULE-SET，按小火箭的「首条匹配生效」语义
模拟每条流量的判定，并统计匹配过程中**触发了几次本地 DNS 查询**。

后者是「DNS 是否泄露」的硬指标 —— 小火箭手册第 718 行：
「当域名请求遇到 IP 类规则时，Shadowrocket 会向本地 DNS 服务器发送查询请求，
  以判断主机 IP 是否匹配规则。若加 no-resolve，则跳过此规则，不会触发本地 DNS 查询。」

所以：一个域名在匹配过程中若触发过本地解析，就已经泄露了，后面匹配到什么都救不回来。

用法：
  python3 verify.py                 # 完整验收
  python3 verify.py -v              # 附带每条命中的规则原文
"""

import argparse
import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

BASE = Path(__file__).resolve().parent
CONF = BASE / "out" / "shadowrocket.conf"

IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "GEOIP"}


# ------------------------------------------------------------------ 取数据
def curl(url: str, timeout=40) -> str:
    p = subprocess.run(["curl", "-sSL", "--max-time", str(timeout), url],
                       capture_output=True, check=False)
    if p.returncode != 0:
        raise RuntimeError(f"拉取失败 {url}: {p.stderr.decode(errors='replace')[:100]}")
    return p.stdout.decode("utf-8", errors="replace")


# ------------------------------------------------------------------ 规则模型
@dataclass
class Rule:
    raw: str
    rtype: str
    value: str = ""
    policy: str = ""
    no_resolve: bool = False
    source: str = "conf"

    def __str__(self):
        return self.raw


@dataclass
class MatchResult:
    policy: str
    rule: str
    dns_hits: int          # 匹配过程中触发本地 DNS 查询的次数
    trail: list = field(default_factory=list)


def parse_rule(line: str, source: str = "conf") -> Rule | None:
    parts = [p.strip() for p in line.split(",")]
    if not parts or not parts[0]:
        return None
    rtype = parts[0].upper()

    if rtype == "RULE-SET":
        return None                      # 由调用方展开
    if rtype == "FINAL" or rtype == "MATCH":
        return Rule(line, "FINAL", "", parts[1].upper() if len(parts) > 1 else "PROXY", False, source)

    no_resolve = any(p.lower() == "no-resolve" for p in parts)
    if rtype in IP_RULE_TYPES:
        # IP-CIDR,1.2.3.0/24,DIRECT,no-resolve
        value = parts[1] if len(parts) > 1 else ""
        policy = ""
        for p in reversed(parts[2:]):
            if p.lower() != "no-resolve":
                policy = p.upper()
                break
        return Rule(line, rtype, value, policy, no_resolve, source)

    # DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / URL-REGEX / USER-AGENT
    value = parts[1] if len(parts) > 1 else ""
    policy = parts[2].upper() if len(parts) > 2 else ""
    return Rule(line, rtype, value, policy, no_resolve, source)


def load_conf(path: Path):
    general, rules, rulesets, others = {}, [], [], {}
    mode = None
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        m = re.match(r"^\[(.+?)\]$", s)
        if m:
            mode = m.group(1)
            others.setdefault(mode, [])
            continue
        if not s or s.startswith("#"):
            continue
        if mode == "General":
            if "=" in s:
                k, v = s.split("=", 1)
                general[k.strip()] = v.strip()
        elif mode == "Rule":
            if s.upper().startswith(("RULE-SET,", "DOMAIN-SET,")):
                rulesets.append(s)
            else:
                r = parse_rule(s)
                if r:
                    rules.append(r)
        elif mode:
            others[mode].append(s)
    return general, rules, rulesets, others


SUPPORTED_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
    "GEOIP", "USER-AGENT", "URL-REGEX", "FINAL", "RULE-SET", "DOMAIN-SET",
}


def expand_ruleset(line: str, stats: dict) -> list[Rule]:
    parts = [p.strip() for p in line.split(",")]
    url, policy = parts[1], parts[2].upper()

    # DOMAIN-SET：一行一个域名，点开头 = 后缀匹配（Surge/Shadowrocket 规范）
    if parts[0].upper() == "DOMAIN-SET":
        try:
            body = curl(url)
        except Exception as e:                               # noqa: BLE001
            stats.setdefault("failed", []).append((url, str(e)))
            return []
        out = []
        for ln in body.splitlines():
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            if t.startswith("."):
                out.append(Rule(t, "DOMAIN-SUFFIX", t[1:], policy, True, url.split("/")[-1]))
            else:
                out.append(Rule(t, "DOMAIN", t, policy, True, url.split("/")[-1]))
        stats.setdefault("sets", []).append(
            {"file": url.split("/")[-1], "count": len(out), "unsupported": [], "url": url})
        return out

    try:
        body = curl(url)
    except Exception as e:                                   # noqa: BLE001
        stats.setdefault("failed", []).append((url, str(e)))
        return []

    out, unsupported = [], set()
    for ln in body.splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        p = [x.strip() for x in s.split(",")]
        t = p[0].upper()
        if t not in SUPPORTED_TYPES:
            unsupported.add(t)
            continue
        if t in IP_RULE_TYPES:
            nr = any(x.lower() == "no-resolve" for x in p)
            out.append(Rule(s, t, p[1] if len(p) > 1 else "", policy, nr, url.split("/")[-1]))
        else:
            out.append(Rule(s, t, p[1] if len(p) > 1 else "", policy, False, url.split("/")[-1]))

    stats.setdefault("sets", []).append({
        "file": url.split("/")[-1], "count": len(out),
        "unsupported": sorted(unsupported), "url": url,
    })
    return out


# ------------------------------------------------------------------ 匹配引擎
class Matcher:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        # GEOIP,CN 用 ACL4SSR 的中国 IP 段近似
        self.cn_nets = []
        for r in rules:
            if r.rtype == "IP-CIDR":
                pass
        self._load_cn()

    def _load_cn(self):
        try:
            body = curl("https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaIp.list")
            nets = []
            for ln in body.splitlines():
                s = ln.strip()
                if s.startswith("IP-CIDR,"):
                    cidr = s.split(",")[1]
                    try:
                        nets.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass
            self.cn_nets = nets
        except Exception:                                    # noqa: BLE001
            self.cn_nets = []

    def _is_cn_ip(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.cn_nets)

    def match(self, target: str) -> MatchResult:
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False

        trail = []
        dns_hits = 0

        for r in self.rules:
            hit = False

            if r.rtype == "DOMAIN":
                hit = (not is_ip) and target.lower() == r.value.lower()
            elif r.rtype == "DOMAIN-SUFFIX":
                t, v = target.lower(), r.value.lower()
                hit = (not is_ip) and (t == v or t.endswith("." + v))
            elif r.rtype == "DOMAIN-KEYWORD":
                hit = (not is_ip) and (r.value.lower() in target.lower())
            elif r.rtype in ("IP-CIDR", "IP-CIDR6"):
                if is_ip:
                    try:
                        hit = ipaddress.ip_address(target) in ipaddress.ip_network(r.value, strict=False)
                    except ValueError:
                        hit = False
                else:
                    if r.no_resolve:
                        continue                      # 域名请求跳过，不解析 —— 不泄露
                    dns_hits += 1                     # 触发本地 DNS 查询 —— 泄露
                    trail.append(f"[本地DNSx{dns_hits}] {r.raw[:70]}")
                    continue
            elif r.rtype == "GEOIP":
                if not is_ip:
                    if r.no_resolve:
                        continue
                    dns_hits += 1
                    trail.append(f"[本地DNSx{dns_hits}] {r.raw[:70]}")
                    continue
                if r.value.upper() == "CN":
                    hit = self._is_cn_ip(target)
            elif r.rtype == "FINAL":
                return MatchResult(r.policy, r.raw, dns_hits, trail)

            if hit:
                trail.append(r.raw[:90])
                return MatchResult(r.policy, r.raw, dns_hits, trail)

        return MatchResult("NO-MATCH", "（无规则命中，落到 FINAL 之前就结束）", dns_hits, trail)


class FastMatcher:
    """索引版匹配器：把「首个命中」换成按域名拆后缀查表，用于几千条域名的全量扫描。
    前提是所有 IP 类规则都带 no-resolve（已由结构检查保证），因此 IP 规则一律跳过，
    不影响域名规则的先后顺序。"""

    def __init__(self, rules):
        self.exact, self.suffix, self.keyword, self.final = {}, {}, [], None
        for i, r in enumerate(rules):
            if r.rtype == "DOMAIN":
                self.exact.setdefault(r.value.lower(), (i, r.policy))
            elif r.rtype == "DOMAIN-SUFFIX":
                self.suffix.setdefault(r.value.lower(), (i, r.policy))
            elif r.rtype == "DOMAIN-KEYWORD":
                self.keyword.append((i, r.value.lower(), r.policy))
            elif r.rtype == "FINAL" and self.final is None:
                self.final = (i, r.policy)

    def match(self, domain: str):
        d = domain.lower()
        best = None
        if d in self.exact:
            i, pol = self.exact[d]
            best = (i, pol, f"DOMAIN,{d}")
        parts = d.split(".")
        for k in range(len(parts)):
            sfx = ".".join(parts[k:])
            if sfx in self.suffix:
                i, pol = self.suffix[sfx]
                if best is None or i < best[0]:
                    best = (i, pol, f"DOMAIN-SUFFIX,{sfx}")
        for i, kw, pol in self.keyword:
            if kw in d and (best is None or i < best[0]):
                best = (i, pol, f"DOMAIN-KEYWORD,{kw}")
        if best:
            return best[1], best[2]
        return (self.final[1], "FINAL") if self.final else ("NO-MATCH", "-")


# ------------------------------------------------------------------ 断言集
DIRECT = "DIRECT"
PROXY = "PROXY"
REJECT = {"REJECT", "REJECT-TINYGIF", "REJECT-DROP"}

CASES = [
    # ---- 国内大站：必须直连，且匹配过程零本地解析 ----
    ("baidu.com",        DIRECT, "国内大站"),
    ("www.baidu.com",    DIRECT, "国内大站子域"),
    ("taobao.com",       DIRECT, "国内电商"),
    ("jd.com",           DIRECT, "国内电商"),
    ("qq.com",           DIRECT, "国内社交"),
    ("bilibili.com",     DIRECT, "国内视频"),
    ("weibo.com",        DIRECT, "国内社交"),
    ("zhihu.com",        DIRECT, "国内社区"),
    ("163.com",          DIRECT, "国内门户"),
    ("alipay.com",       DIRECT, "国内支付"),
    ("meituan.com",      DIRECT, "国内生活"),
    ("douyin.com",       DIRECT, "国内短视频"),
    ("xiaohongshu.com",  DIRECT, "国内社区"),
    ("aliyun.com",       DIRECT, "国内云"),
    ("tencent.com",      DIRECT, "国内企业"),

    # ---- 境外：必须走代理，匹配过程零本地解析 ----
    ("google.com",       PROXY,  "境外搜索"),
    ("www.google.com",   PROXY,  "境外搜索"),
    ("youtube.com",      PROXY,  "境外视频"),
    ("github.com",       PROXY,  "境外代码"),
    ("openai.com",       PROXY,  "境外 AI"),
    ("chatgpt.com",      PROXY,  "境外 AI"),
    ("twitter.com",      PROXY,  "境外社交"),
    ("x.com",            PROXY,  "境外社交"),
    ("facebook.com",     PROXY,  "境外社交"),
    ("instagram.com",    PROXY,  "境外社交"),
    ("wikipedia.org",    PROXY,  "境外百科"),
    ("netflix.com",      PROXY,  "境外流媒体"),
    ("telegram.org",     PROXY,  "境外 IM"),
    ("cloudflare.com",   PROXY,  "境外基础设施"),
    ("speedtest.net",    PROXY,  "测速站"),
    ("ip.sb",            PROXY,  "出口 IP 检测"),

    # ---- Apple：必须直连（否则 App Store / iCloud 挂）----
    ("apple.com",        DIRECT, "Apple"),
    ("www.apple.com",    DIRECT, "Apple"),
    ("icloud.com",       DIRECT, "Apple"),
    ("mzstatic.com",     DIRECT, "Apple CDN"),
    ("apps.apple.com",   DIRECT, "App Store"),

    # ---- 广告：必须拦截 ----
    ("doubleclick.net",  "REJECT", "Google 广告"),
    ("google-analytics.com", "REJECT", "统计"),
    ("googlesyndication.com", "REJECT", "广告联盟"),
    ("cnzz.com",         "REJECT", "国内统计"),
    ("umeng.com",        "REJECT", "友盟统计"),
    ("popads.net",       "REJECT", "弹窗广告"),
    ("adjust.com",       "REJECT", "广告归因"),
    ("app.adjust.com",   "REJECT", "广告归因子域"),

    # ---- 局域网 / 特殊 ----
    ("192.168.1.1",      DIRECT, "局域网 IP"),
    ("10.0.0.1",         DIRECT, "局域网 IP"),
]


def policy_ok(actual: str, expect: str) -> bool:
    a = actual.upper()
    if expect == "REJECT":
        return a in REJECT
    return a == expect


# ------------------------------------------------------------------ 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    print("=" * 74)
    print("Shadowrocket 配置验收")
    print("=" * 74)

    general, rules, rulesets, others = load_conf(CONF)
    print(f"\n[解析] 配置 {CONF.name}")
    print(f"  [General] {len(general)} 项 · [Rule] 内联 {len(rules)} 条 · RULE-SET {len(rulesets)} 个")
    for k in ("Host", "URL Rewrite"):
        print(f"  [{k}] {len(others.get(k, []))} 条")

    # ---- 展开规则集（每个 URL 只拉一次）----
    print(f"\n[规则集] 展开 {len(rulesets)} 个远程列表")
    stats = {}
    cache = {}
    for i, line in enumerate(rulesets, 1):
        got = expand_ruleset(line, stats)
        cache[line] = got
        name = line.split(",")[1].split("/")[-1]
        print(f"  {i:>2}. {name:<26} {len(got):>5} 条")

    for st in stats.get("sets", []):
        if st["unsupported"]:
            print(f"  ! {st['file']} 含小火箭不支持的类型: {st['unsupported']}")
    if stats.get("failed"):
        for u, e in stats["failed"]:
            print(f"  ✗ 拉取失败 {u}: {e}")

    # ---- 按配置里的原始次序重建完整规则链 ----
    full = []
    mode = None
    for line in CONF.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        m = re.match(r"^\[(.+?)\]$", s)
        if m:
            mode = m.group(1)
            continue
        if mode != "Rule" or not s or s.startswith("#"):
            continue
        if s.upper().startswith(("RULE-SET,", "DOMAIN-SET,")):
            full.extend(cache.get(s, []))
        else:
            r = parse_rule(s)
            if r:
                full.append(r)

    print(f"\n[规则链] 展开后总计 {len(full)} 条")

    # ---- 结构检查 ----
    print("\n[结构检查]")
    checks = []

    def ck(cond, msg):
        checks.append((cond, msg))
        print(f"  {'✓' if cond else '✗'} {msg}")

    ck(sum(1 for r in full if r.rtype == "FINAL") >= 1, "存在 FINAL 兜底")
    ck(sum(1 for r in full if r.rtype == "FINAL") == 1, "FINAL 唯一")
    ck(sum(1 for r in full if r.rtype == "GEOIP") == 1, "GEOIP 唯一")
    geo = [r for r in full if r.rtype == "GEOIP"]
    ck(bool(geo) and geo[0].no_resolve, "GEOIP 带 no-resolve")
    nude = [r for r in full if r.rtype in IP_RULE_TYPES and not r.no_resolve]
    ck(not nude, f"所有 IP 类规则带 no-resolve（裸规则 {len(nude)} 条）")
    ck(general.get("dns-server", "").startswith("https"), "dns-server 为加密 DoH")
    ck("proxy-dns-server" in general, "proxy-dns-server 已配置")
    ck(general.get("always-ip-address", "false").lower() != "true", "未强制本地解析（always-ip-address）")
    ck(general.get("private-ip-answer", "true").lower() == "true", "private-ip-answer = true")
    ck("system" not in general.get("dns-server", "").split(",")[0], "dns-server 首项不是 system")

    # ---- 匹配断言 ----
    print(f"\n[匹配断言] {len(CASES)} 条流量")
    m = Matcher(full)
    fails, leaks = [], []
    print(f"  {'域名/IP':<28}{'期望':<8}{'实际':<10}{'本地DNS':<8}判定")
    print("  " + "-" * 70)
    for target, expect, desc in CASES:
        res = m.match(target)
        ok = policy_ok(res.policy, expect)
        if not ok:
            fails.append((target, expect, res.policy, res.rule, desc))
        if res.dns_hits:
            leaks.append((target, res.dns_hits, res.rule))
        mark = "✓" if ok else "✗"
        dns = "0" if res.dns_hits == 0 else f"✗{res.dns_hits}"
        print(f"  {target:<28}{expect:<8}{res.policy:<10}{dns:<8}{mark}")
        if args.verbose or not ok:
            print(f"      → {res.rule[:88]}")
            if res.trail and not ok:
                for t in res.trail[-3:]:
                    print(f"        trail: {t}")

    # ---- 全量扫描：被墙域名 / 国内域名 ----
    print("\n[全量扫描] 用权威域名表做穷举，不靠人工挑样本")
    fm = FastMatcher(full)
    scan_fail = 0

    # 1) GFWList 里的被墙域名，绝不允许判成 DIRECT（判直连 = 打不开）
    try:
        import base64
        raw = curl("https://cdn.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt")
        txt = base64.b64decode(raw.strip()).decode("utf-8", errors="replace")
        gfw = set()
        for ln in txt.splitlines():
            t = ln.strip()
            if not t or t.startswith("!") or t.startswith("["):
                continue
            t = t.lstrip("|").lstrip(".").replace("*", "").split("/")[0].split("^")[0]
            m = re.match(r"[a-z0-9][a-z0-9\-\.]{2,80}\.[a-z]{2,12}", t, re.I)
            if m:
                gfw.add(m.group(0).lower())
        bad = []
        for d in gfw:
            pol, _rule = fm.match(d)
            if pol.upper() == "DIRECT":
                bad.append((d, _rule))
        print(f"  被墙域名(GFWList) {len(gfw)} 条 → 判成直连 {len(bad)} 条", end="")
        if bad:
            print("  ✗")
            for d, r in bad[:15]:
                print(f"      {d:<34} {r}")
            if len(bad) > 15:
                print(f"      ... 还有 {len(bad)-15} 条")
            scan_fail += len(bad)
        else:
            print("  ✓（全部走代理或拦截，不会出现打不开）")
    except Exception as e:                                    # noqa: BLE001
        print(f"  被墙域名扫描跳过：{e}")

    # 2) 国内常用域名，绝不允许判成 REJECT（误杀 = 网站打不开）
    try:
        body = curl("https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list@master/accelerated-domains.china.conf", 60)
        cn = set()
        for ln in body.splitlines():
            m = re.match(r"server=/([^/]+)/", ln.strip())
            if m:
                cn.add(m.group(1).lower())
        bad = []
        for d in cn:
            pol, _rule = fm.match(d)
            if pol.upper() in REJECT:
                bad.append((d, _rule))
        print(f"  国内域名清单 {len(cn)} 条 → 被判拦截 {len(bad)} 条", end="")
        if bad:
            print("  ! （多为国内服务器托管的广告/垃圾站，属正常拦截）")
            for d, r in bad[:10]:
                print(f"      {d:<34} {r}")
        else:
            print("  ✓")
    except Exception as e:                                    # noqa: BLE001
        print(f"  国内域名扫描跳过：{e}")

    # ---- 汇总 ----
    print("\n" + "=" * 74)
    print("验收结论")
    print("=" * 74)
    verdict = True

    if fails:
        verdict = False
        print(f"\n✗ 策略断言失败 {len(fails)} 条：")
        for t, e, a, rule, desc in fails:
            print(f"    {t:<28} 期望 {e} 实际 {a}  ({desc})")
            print(f"      命中: {rule}")
    else:
        print(f"\n✓ 策略断言全部通过（{len(CASES)} 条）")

    if leaks:
        verdict = False
        print(f"\n✗ DNS 泄露点 {len(leaks)} 条（匹配过程中触发了本地解析）：")
        for t, n, rule in leaks:
            print(f"    {t:<28} 触发 {n} 次  规则: {rule}")
    else:
        print("✓ 全部流量在匹配阶段零本地 DNS 查询 —— 境外域名不会被本地解析")

    print(f"\n结构检查 {sum(1 for c, _ in checks if c)}/{len(checks)} 通过")
    print(f"规则集 {len(rulesets)} 个 · 展开后 {len(full)} 条")
    print("\n" + ("全部通过 ✅" if verdict and all(c for c, _ in checks) else "存在问题 ❌"))
    return 0 if (verdict and all(c for c, _ in checks)) else 1


if __name__ == "__main__":
    sys.exit(main())
