"""验收器共用的取源、DNS 报文与兼容性检查；不代表客户端实际流量。"""

import base64
import ipaddress
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


COMPATIBILITY_CASES = [
    ("xp.apple.com", "DIRECT", "Apple 软件更新配置保活"),
    ("clientstream.launchdarkly.com", "PROXY", "LaunchDarkly 功能配置流保活"),
    ("clientsdk.launchdarkly.com", "PROXY", "LaunchDarkly 客户端配置保活"),
    ("sdk.split.io", "PROXY", "Split 功能开关 SDK 保活"),
    ("app.link", "PROXY", "Branch 深度跳转链接保活"),
]
DNS_FIELDS = ("dns-server", "proxy-dns-server", "fallback-dns-server")
RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
              "IP-CIDR6", "GEOIP", "URL-REGEX", "USER-AGENT", "DEST-PORT"}
BUILD_ANTI_AD_URL = "https://beifang35.github.io/shadowrocket-config/rules/anti-ad.txt"


def fetch_text(url, base, timeout=40, *, source_mode="remote"):
    """remote 始终联网；build 仅替换本项目精确 URL 为待发布的本地产物。

    构建产物缺失时直接失败，不能回退到线上旧版本后误验收通过。
    """
    if source_mode not in ("remote", "build"):
        raise ValueError(f"未知取源模式: {source_mode}")
    if source_mode == "build" and url == BUILD_ANTI_AD_URL:
        body = (Path(base) / "rules" / "anti-ad.txt").read_text(encoding="utf-8")
    else:
        p = subprocess.run(["curl", "--fail", "-sSL", "--max-time", str(timeout), url],
                           capture_output=True, check=False)
        if p.returncode:
            raise RuntimeError(f"拉取失败 {url} (curl={p.returncode}): "
                               f"{p.stderr.decode(errors='replace')[:160]}")
        body = p.stdout.decode("utf-8", errors="strict")
    if not body.strip():
        raise ValueError(f"空响应: {url}")
    return body


def require_items(items, source):
    if not items:
        raise ValueError(f"{source}: 没有可验收的条目")
    return items


def valid_domain(value):
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return len(value) <= 253 and all(
        # 规则可匹配 DNS 标签（上游含 fc-.cdn.bcebos.com），不强加主机名端点限制。
        re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", label)
        for label in value.split("."))


def parse_source(body, kind, source):
    """拒绝空集、HTML/错误文本及不支持的规则，避免缺规则仍报通过。"""
    out = []
    for line_no, line in enumerate(body.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", "!")):
            continue
        if kind == "DOMAIN-SET":
            t, value = ("DOMAIN-SUFFIX", s[1:]) if s.startswith(".") else ("DOMAIN", s)
            nr = True
        else:
            parts = [p.strip() for p in s.split(",")]
            t, value = parts[0].upper(), parts[1] if len(parts) > 1 else ""
            if t == "DST-PORT":
                t = "DEST-PORT"
            nr = any(p.lower() == "no-resolve" for p in parts[2:])
            if t not in RULE_TYPES:
                raise ValueError(f"{source}:{line_no}: 不支持的规则类型 {t[:60]}")
        if not value or (t in ("DOMAIN", "DOMAIN-SUFFIX") and not valid_domain(value)):
            raise ValueError(f"{source}:{line_no}: 非法规则值 {value[:80]!r}")
        if t in ("IP-CIDR", "IP-CIDR6"):
            net = ipaddress.ip_network(value, strict=False)
            # Shadowrocket 的 IP-CIDR 同时支持 IPv4/IPv6；IP-CIDR6 只支持 IPv6。
            if t == "IP-CIDR6" and net.version != 6:
                raise ValueError(f"{source}:{line_no}: IP 版本与规则不符")
        if t == "DEST-PORT" and (not value.isdecimal() or not 1 <= int(value) <= 65535):
            raise ValueError(f"{source}:{line_no}: 本验收器仅支持单个有效目的端口")
        out.append((t, value, nr))
    return require_items(out, source)


def secure_doh_url(url):
    try:
        p = urlsplit(url)
        return p.scheme == "https" and bool(p.hostname) and not p.username and not p.fragment
    except ValueError:
        return False


def dns_servers(general):
    return {key: [u.strip() for u in general.get(key, "").split(",") if u.strip()]
            for key in DNS_FIELDS}


def dns_checks(general):
    servers = dns_servers(general)
    checks = [(bool(servers[key]) and all(map(secure_doh_url, servers[key])),
               f"{key} 全部为有效 HTTPS DoH") for key in DNS_FIELDS[:2]]
    checks.append(("fallback-dns-server" not in general or
                   (bool(servers[DNS_FIELDS[2]]) and all(map(secure_doh_url, servers[DNS_FIELDS[2]]))),
                   "fallback-dns-server 未配置或全部为 HTTPS DoH（禁止明文回退）"))
    checks.append((general.get("dns-direct-system", "").lower() == "false",
                   "dns-direct-system = false"))
    checks.append(("*:53" in {value.strip() for value in general.get("hijack-dns", "").split(",")},
                   "hijack-dns 包含原生 *:53 接管（静态设置检查）"))
    return checks


def _name(packet, offset):
    labels, seen, end = [], set(), None
    while True:
        if offset >= len(packet) or offset in seen:
            raise ValueError("DNS 名称越界或压缩指针循环")
        seen.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError("DNS 压缩指针截断")
            target = ((length & 0x3f) << 8) | packet[offset + 1]
            if target < 12 or target >= offset:
                raise ValueError("DNS 压缩指针无效")
            end = end if end is not None else offset + 2
            offset = target
            continue
        if length & 0xc0 or offset + 1 + length > len(packet):
            raise ValueError("DNS 标签无效或截断")
        offset += 1
        if not length:
            break
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
        if sum(len(label) + 1 for label in labels) > 254:
            raise ValueError("DNS 名称过长")
    return ".".join(labels), end if end is not None else offset


@dataclass(frozen=True)
class DNSResponse:
    rcode: int
    addresses: tuple


def parse_dns_response(packet, query_name="baidu.com", query_type=1):
    """解析完整 wire response；合法 SERVFAIL 可解析，但不等于解析成功。

    DoH 的关联依据是 HTTP 请求与 question；不把 DNS ID 当安全边界。
    """
    if len(packet) < 12:
        raise ValueError("DNS 报文头截断")
    _ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    if not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or qd != 1:
        raise ValueError("DNS response 标志、截断位或 question 数量无效")
    name, offset = _name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("DNS question 截断")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    offset += 4
    if (name, qtype, qclass) != (query_name.lower().rstrip("."), query_type, 1):
        raise ValueError("DNS question 与请求不符")
    answers, aliases, rcode = [], {}, flags & 15
    for index in range(an + ns + ar):
        owner, offset = _name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("DNS 资源记录头截断")
        rtype, rclass, ttl, size = struct.unpack_from("!HHIH", packet, offset)
        start, end = offset + 10, offset + 10 + size
        if end > len(packet):
            raise ValueError("DNS 资源记录数据截断")
        if rtype in (1, 28):
            if size != (4 if rtype == 1 else 16):
                raise ValueError("DNS 地址记录长度无效")
            if index < an and rclass == 1 and rtype == query_type:
                answers.append((owner, str(ipaddress.ip_address(packet[start:end]))))
        elif rtype == 5:
            alias, consumed = _name(packet, start)
            if consumed != end:
                raise ValueError("DNS CNAME 长度无效")
            if index < an and rclass == 1:
                aliases[owner] = alias
        elif rtype == 41 and index >= an + ns:
            rcode |= (ttl >> 24) << 4
        offset = end
    if offset != len(packet):
        raise ValueError("DNS 报文含未解析的尾部数据")
    reachable, current = set(), name
    while current not in reachable:
        reachable.add(current)
        if current not in aliases:
            break
        current = aliases[current]
    return DNSResponse(rcode, tuple(address for owner, address in answers if owner in reachable))


def probe_doh(url, timeout=8, query_name="baidu.com"):
    labels = query_name.rstrip(".").encode("ascii").split(b".")
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
    query = struct.pack("!6H", 0, 0x100, 1, 0, 0, 0) + question
    purl = urlsplit(url)
    params = [(k, v) for k, v in parse_qsl(purl.query) if k != "dns"]
    params.append(("dns", base64.urlsafe_b64encode(query).rstrip(b"=").decode()))
    target = urlunsplit(purl._replace(query=urlencode(params)))
    with tempfile.TemporaryDirectory(prefix="shadowrocket-doh-") as temp:
        body_path = Path(temp) / "response.dns"
        p = subprocess.run(
            ["curl", "--fail", "-sS", "--max-time", str(timeout), "-H", "Accept: application/dns-message",
             "-o", str(body_path), "-w", "%{http_code}\n%{content_type}", target],
            capture_output=True, text=True, check=False)
        if p.returncode:
            raise RuntimeError(f"curl={p.returncode}: {p.stderr.strip()[:160]}")
        metadata = p.stdout.strip().splitlines()
        if len(metadata) != 2 or metadata[0] != "200" or metadata[1].split(";", 1)[0].strip().lower() != "application/dns-message":
            raise ValueError(f"DoH HTTP 状态/类型无效: {p.stdout.strip()!r}")
        response = parse_dns_response(body_path.read_bytes(), query_name)
    if response.rcode != 0:
        raise ValueError(f"DNS 报文格式有效，但 {query_name} 解析失败 (RCODE={response.rcode})")
    if not response.addresses:
        raise ValueError(f"DNS 报文格式有效，但 {query_name} 没有匹配的 A 记录")
    return f"HTTP 200 · A={','.join(response.addresses)}"
