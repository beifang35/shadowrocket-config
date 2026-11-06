"""回归已知假阳性；全部使用本地短生命周期服务器或确定性响应。"""

import base64
import contextlib
import io
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import verify
import verify_live
import verify_support as support


def wire_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_packet(rcode=0, answer=True, owner=b"\xc0\x0c", ident=0):
    question = wire_name("baidu.com") + struct.pack("!HH", 1, 1)
    record = owner + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4]) if answer else b""
    return struct.pack("!6H", ident, 0x8180 | rcode, 1, int(answer), 0, 0) + question + record


class SourceTests(unittest.TestCase):
    def test_real_curl_rejects_http_error_and_empty_response(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = {"/ok": b".ads.test\n", "/error": b".ads.test\n", "/empty": b""}[self.path]
                self.send_response(404 if self.path == "/error" else 200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                url = f"http://127.0.0.1:{server.server_port}"
                self.assertEqual(support.fetch_text(url + "/ok", temp, 2), ".ads.test\n")
                for path in ("/error", "/empty"):
                    with self.subTest(path=path), self.assertRaises((ValueError, RuntimeError)):
                        support.fetch_text(url + path, temp, 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_rules_reject_html_comments_only_and_invalid_records(self):
        for kind, body in [("DOMAIN-SET", "# nothing"), ("RULE-SET", "# nothing"),
                           ("DOMAIN-SET", "<html>HTTP error</html>"),
                           ("RULE-SET", "HTTP 200 but not rules"),
                           ("RULE-SET", "DOMAIN,"), ("RULE-SET", "IP-CIDR6,1.2.3.0/24")]:
            with self.subTest(kind=kind, body=body), self.assertRaises(ValueError):
                support.parse_source(body, kind, "fixture")

    def test_ip_cidr_accepts_both_families_and_ip_cidr6_accepts_ipv6(self):
        # 官方 default.conf 使用 IP-CIDR,2620:149::/32；不能按 IPv4 专用语法拒绝。
        body = ("IP-CIDR,192.0.2.0/24,no-resolve\n"
                "IP-CIDR,2620:149::/32,no-resolve\n"
                "IP-CIDR6,2001:db8::/32,no-resolve\n")
        self.assertEqual(support.parse_source(body, "RULE-SET", "fixture"), [
            ("IP-CIDR", "192.0.2.0/24", True),
            ("IP-CIDR", "2620:149::/32", True),
            ("IP-CIDR6", "2001:db8::/32", True),
        ])

    def test_anti_ad_404_from_other_host_is_never_shadowed_by_local_file(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                local = Path(temp) / "rules" / "anti-ad.txt"
                local.parent.mkdir()
                local.write_text(".local-build.test\n", encoding="utf-8")
                url = f"http://127.0.0.1:{server.server_port}/rules/anti-ad.txt"
                for kwargs in ({}, {"source_mode": "remote"}, {"source_mode": "build"}):
                    with self.subTest(kwargs=kwargs), self.assertRaisesRegex(RuntimeError, "curl=22"):
                        support.fetch_text(url, temp, 2, **kwargs)
                self.assertEqual(requests, ["/rules/anti-ad.txt"] * 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_published_anti_ad_only_uses_local_file_in_explicit_build_mode(self):
        url = "https://beifang35.github.io/shadowrocket-config/rules/anti-ad.txt"
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "rules" / "anti-ad.txt"
            local.parent.mkdir()
            local.write_text(".local-build.test\n", encoding="utf-8")
            failure = subprocess.CompletedProcess([], 22, b"", b"HTTP 404")
            with patch.object(support.subprocess, "run", return_value=failure) as curl:
                self.assertEqual(support.fetch_text(url, temp, source_mode="build"), ".local-build.test\n")
                curl.assert_not_called()
                for kwargs in ({}, {"source_mode": "remote"}):
                    with self.subTest(kwargs=kwargs), self.assertRaisesRegex(RuntimeError, "HTTP 404"):
                        support.fetch_text(url, temp, **kwargs)
                self.assertEqual(curl.call_count, 2)
                self.assertTrue(all(call.args[0][-1] == url for call in curl.call_args_list))

    def test_build_cannot_fall_back_to_remote_when_artifact_is_missing_or_empty(self):
        url = "https://beifang35.github.io/shadowrocket-config/rules/anti-ad.txt"
        with tempfile.TemporaryDirectory() as temp, patch.object(support.subprocess, "run") as curl:
            with self.assertRaises(FileNotFoundError):
                support.fetch_text(url, temp, source_mode="build")
            local = Path(temp) / "rules" / "anti-ad.txt"
            local.parent.mkdir()
            local.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "空响应"):
                support.fetch_text(url, temp, source_mode="build")
            curl.assert_not_called()

    def test_upstream_dns_label_is_not_mistaken_for_a_host_name_error(self):
        self.assertEqual(support.parse_source("DOMAIN,fc-.cdn.bcebos.com", "RULE-SET", "fixture"),
                         [("DOMAIN", "fc-.cdn.bcebos.com", False)])


class DoHTests(unittest.TestCase):
    def probe(self, body, returncode=0, metadata="200\napplication/dns-message"):
        def fake_curl(args, **_kwargs):
            Path(args[args.index("-o") + 1]).write_bytes(body)
            return subprocess.CompletedProcess(args, returncode, metadata, "injected transport error")
        with patch.object(support.subprocess, "run", side_effect=fake_curl):
            return support.probe_doh("https://resolver.test/dns-query?existing=1")

    def test_success_is_a_parsed_answer_and_id_is_not_a_security_boundary(self):
        self.assertIn("A=1.2.3.4", self.probe(dns_packet(ident=1234)))

    def test_compressed_cname_chain_is_accepted(self):
        question = wire_name("baidu.com") + struct.pack("!HH", 1, 1)
        cname = wire_name("www.baidu.com")
        records = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(cname)) + cname
        records += cname + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([5, 6, 7, 8])
        packet = struct.pack("!6H", 0, 0x8180, 1, 2, 0, 0) + question + records
        self.assertIn("A=5.6.7.8", self.probe(packet))

    def test_http_200_type_alone_cannot_pass(self):
        for body in (b"", b"not DNS", dns_packet()[:-1], dns_packet(answer=False),
                     dns_packet(owner=wire_name("unrelated.test"))):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.probe(body)
        with self.assertRaises(RuntimeError):
            self.probe(dns_packet(), returncode=18)
        with self.assertRaises(ValueError):
            self.probe(dns_packet(), metadata="200\ntext/html")

    def test_servfail_is_valid_wire_but_resolution_failure(self):
        packet = dns_packet(rcode=2, answer=False)
        self.assertEqual(support.parse_dns_response(packet).rcode, 2)
        with self.assertRaisesRegex(ValueError, "格式有效.*解析失败.*RCODE=2"):
            self.probe(packet)

    def test_wrong_question_and_bad_compression_cannot_pass(self):
        wrong = dns_packet().replace(b"baidu", b"wrong")
        loop = dns_packet(owner=b"\xc0\x1b")
        for body in (wrong, loop):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.probe(body)


GENERAL = {
    "hijack-dns": "*:53",
    "dns-server": "https://primary.test/dns-query",
    "proxy-dns-server": "https://proxy-only.test/dns-query",
    "fallback-dns-server": "https://fallback-only.test/dns-query",
    "dns-direct-system": "false", "always-ip-address": "false", "private-ip-answer": "true",
}
SOURCE = "https://rules.test/list"
GFW = "https://cdn.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt"
CN = "https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list@master/accelerated-domains.china.conf"


def fixture_config(general):
    policies = {d: p for d, p, _ in verify.CASES}
    policies.update(verify_live.WHITE)
    rules = ["DEST-PORT,53,PROXY"] + [f"IP-CIDR,{d}/32,{p},no-resolve" if d[0].isdigit() and d.count(".") == 3
             else f"DOMAIN,{d},{p}" for d, p in policies.items()]
    rules += [f"DOMAIN-SET,{SOURCE},REJECT", "GEOIP,CN,DIRECT,no-resolve", "FINAL,REJECT"]
    return "[General]\n" + "\n".join(f"{k} = {v}" for k, v in general.items()) + "\n[Rule]\n" + "\n".join(rules)


class AcceptanceTests(unittest.TestCase):
    def test_native_editor_mixed_case_sections_are_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "shadowrocket.db"
            with sqlite3.connect(path) as con:
                con.execute("CREATE TABLE config(section,name,value,option,ext)")
                con.executemany("INSERT INTO config VALUES(?,?,?,?,?)", [
                    ("general", "dns-server", "https://dns.test/query", "", ""),
                    ("General", "hijack-dns", "*:53", "", ""),
                    ("Rule", "DEST-PORT", "53", "PROXY", ""),
                ])
            with patch.object(verify_live, "DB", path):
                rows, general = verify_live.load_db()
            self.assertEqual(general["hijack-dns"], "*:53")
            self.assertEqual(rows[0][1:4], ("DEST-PORT", "53", "PROXY"))

    def test_dns_port_guard_beats_domestic_ip_direct_without_changing_https(self):
        lines = ["DEST-PORT,53,PROXY", "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve", "FINAL,PROXY"]
        with patch.object(verify.Matcher, "_load_cn", return_value=None):
            model = verify.Matcher([verify.parse_rule(line) for line in lines])
        device = verify_live.M([("DEST-PORT", "53", "PROXY", False, False, "inline"),
                                ("IP-CIDR", "223.5.5.5/32", "DIRECT", True, False, "inline"),
                                ("FINAL", "", "PROXY", False, False, "inline")])
        self.assertEqual(model.match("223.5.5.5", port=53).policy, "PROXY")
        self.assertEqual(model.match("223.5.5.5", port=443).policy, "DIRECT")
        self.assertEqual(device.match("223.5.5.5", port=53)[0], "PROXY")
        self.assertEqual(device.match("223.5.5.5", port=443)[0], "DIRECT")

    def test_missing_or_partial_dns_hijack_cannot_pass(self):
        for live in (False, True):
            for value in ("", ":53", "8.8.8.8:53"):
                with self.subTest(live=live, value=value):
                    result, output, _ = self.run_acceptance(live=live, settings={"hijack-dns": value})
                    self.assertEqual(result, 1, output)

    def run_acceptance(self, live=False, sources=None, settings=None, probe=None):
        sources = sources or {}
        general = GENERAL | (settings or {})

        def fetch(url, *_args):
            result = sources.get(url)
            if isinstance(result, Exception):
                raise result
            if result is not None:
                return result
            if url == GFW:
                return base64.b64encode(b"||google.com^\n").decode()
            if url == CN:
                return "server=/baidu.com/114.114.114.114\n"
            if url.endswith("/ChinaIp.list"):
                return "IP-CIDR,1.0.1.0/24,no-resolve\n"
            return ".doubleclick.net\n"

        module = verify_live if live else verify
        probe = probe or Mock(return_value="HTTP 200 · A=1.2.3.4")
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            config = Path(temp) / "shadowrocket.conf"
            config.write_text(fixture_config(general), encoding="utf-8")
            stack.enter_context(patch.object(module, "BASE", Path(temp)))
            stack.enter_context(patch.object(verify, "CONF", config))
            stack.enter_context(patch.object(module, "curl", side_effect=fetch))
            stack.enter_context(patch.object(verify_live, "probe_doh", probe))
            stack.enter_context(patch.object(sys, "argv", ["verify_live.py", "--conf"] if live else ["verify.py"]))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            result = module.main()
        return result, output.getvalue(), probe

    def test_complete_valid_fixtures_pass_and_proxy_only_doh_is_probed(self):
        for live in (False, True):
            result, output, probe = self.run_acceptance(live=live)
            self.assertEqual(result, 0, output)
            if live:
                self.assertEqual({call.args[0] for call in probe.call_args_list}, set(GENERAL[k] for k in support.DNS_FIELDS))

    def test_critical_compatibility_cases_are_shared_with_device_acceptance(self):
        for domain, policy, _ in support.COMPATIBILITY_CASES:
            self.assertIn((domain, policy), verify_live.WHITE)
            self.assertIn((domain, policy), [(d, p) for d, p, _ in verify.CASES])

    def test_missing_rule_source_cannot_pass_either_acceptance(self):
        for live in (False, True):
            for body in ("", "# empty list", "<html>failure</html>", RuntimeError("HTTP 404")):
                with self.subTest(live=live, body=body):
                    result, output, _ = self.run_acceptance(live=live, sources={SOURCE: body})
                    self.assertEqual(result, 1, output)

    def test_failed_and_empty_full_scans_are_failures(self):
        for url, body in ((GFW, ""), (GFW, base64.b64encode(b"! comments only").decode()),
                          (GFW, RuntimeError("HTTP 404")), (CN, "# comments only"), (CN, "<html>error</html>")):
            with self.subTest(url=url, body=body):
                result, output, _ = self.run_acceptance(sources={url: body})
                self.assertEqual(result, 1, output)

    def test_plaintext_main_proxy_or_fallback_dns_cannot_pass(self):
        for key in support.DNS_FIELDS:
            for live in (False, True):
                with self.subTest(key=key, live=live):
                    result, output, _ = self.run_acceptance(live=live, settings={key: "https://valid.test/dns-query, system"})
                    self.assertEqual(result, 1, output)

    def test_failed_or_empty_ad_sampling_is_a_failure(self):
        url = "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/reject.txt"
        for body in ("# empty", RuntimeError("HTTP 404"), ".apple.com\n"):
            with self.subTest(body=body):
                result, output, _ = self.run_acceptance(live=True, sources={url: body})
                self.assertEqual(result, 1, output)

    def test_doh_resolution_error_propagates_to_live_verdict(self):
        result, output, _ = self.run_acceptance(live=True, probe=Mock(side_effect=ValueError("RCODE=2")))
        self.assertEqual(result, 1, output)


class ReleaseGateTests(unittest.TestCase):
    def test_publish_stops_before_sync_or_git_when_regression_or_acceptance_fails(self):
        for failed_command in ("-m", "verify.py"):
            with self.subTest(failed_command=failed_command), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                shutil.copyfile(verify.BASE / "publish.sh", root / "publish.sh")
                commands = root / "bin"
                commands.mkdir()
                log = root / "actions.log"
                for command in ("python3", "cp", "git", "curl"):
                    executable = commands / command
                    executable.write_text(
                        '#!/bin/sh\n'
                        'printf "%s %s\\n" "$(basename "$0")" "$*" >> "$ACTION_LOG"\n'
                        'if [ "$1" = "$FAILED_COMMAND" ]; then exit 9; fi\n', encoding="utf-8")
                    executable.chmod(0o755)
                env = os.environ | {"PATH": str(commands) + os.pathsep + os.environ["PATH"],
                                    "ACTION_LOG": str(log), "FAILED_COMMAND": failed_command}
                result = subprocess.run(["bash", str(root / "publish.sh"), "--dry-run"],
                                        env=env, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                actions = log.read_text().splitlines()
                self.assertEqual(actions[0], "python3 merge.py")
                self.assertTrue(any("unittest discover" in line for line in actions))
                self.assertFalse(any(line.startswith(("cp ", "git ", "curl ")) for line in actions), actions)
                if failed_command == "verify.py":
                    self.assertEqual(actions[-1], "python3 verify.py")


if __name__ == "__main__":
    unittest.main()
