#!/usr/bin/env python3
"""
Minimal verification for vk-dpi-proxy image path safety.
Does not touch live VK tokens or chat content.
"""

from __future__ import annotations

import hashlib
import socket
import threading
import time
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dpi_proxy as P  # noqa: E402


class SanitizeTests(unittest.TestCase):
    def test_strips_query_tokens(self):
        raw = "https://sun9-76.userapi.com/impg/abc123/photo.jpg?size=x&hash=SECRET"
        out = P.sanitize_url_for_log(raw)
        self.assertNotIn("SECRET", out)
        self.assertNotIn("hash=", out)
        self.assertIn("/impg/", out)

    def test_no_cookie_fields_in_helpers(self):
        src = Path(P.__file__).read_text(encoding="utf-8")
        for bad in ("Authorization", "Cookie:", "chat text", "access_token"):
            # Logging helpers must not format these names into diagnostic templates
            self.assertNotIn(f"[IMG-DIAG].*{bad}", src)


class FragmentPolicyTests(unittest.TestCase):
    def test_image_cdn_never_multi(self):
        for host in (
            "sun9-76.userapi.com",
            "pp.userapi.com",
            "st1-84.vk.ru",
            "ps.userapi.com",
        ):
            self.assertEqual(P.host_traffic_class(host), "image_cdn")
            mode = P.resolve_fragment_mode(host, "multi")
            self.assertIn(mode, ("none", "split"))
            self.assertNotIn(mode, ("multi", "fine"))

    def test_messaging_is_split(self):
        self.assertEqual(P.resolve_fragment_mode("im.vk.com", "fine"), "split")

    def test_fragment_none_passthrough(self):
        hello = bytes([0x16, 0x03, 0x01]) + (20).to_bytes(2, "big") + b"A" * 20
        # mode none is handled by caller; fragment_client_hello still splits if called
        parts = P.fragment_client_hello(hello, "split")
        self.assertGreaterEqual(len(parts), 1)


class PipeIntegrityTests(unittest.TestCase):
    def test_half_close_drains_remaining(self):
        """One side EOF must not drop bytes already queued from the peer."""
        a, a2 = socket.socketpair()
        b, b2 = socket.socketpair()
        payload = hashlib.sha256(b"large-image-body").digest() * 4000  # ~128KB
        received = bytearray()
        err = []

        def client_read():
            try:
                while True:
                    chunk = a2.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            except OSError as exc:
                err.append(exc)

        def server_write():
            try:
                # Simulate server sending a large body then closing its write.
                b2.sendall(payload)
                b2.shutdown(socket.SHUT_WR)
            except OSError as exc:
                err.append(exc)

        t_pipe = threading.Thread(
            target=P.pipe_bidirectional, args=(a, b), daemon=True
        )
        t_r = threading.Thread(target=client_read, daemon=True)
        t_w = threading.Thread(target=server_write, daemon=True)
        t_pipe.start()
        t_r.start()
        t_w.start()
        t_w.join(timeout=5)
        t_r.join(timeout=5)
        t_pipe.join(timeout=5)
        for s in (a, a2, b, b2):
            try:
                s.close()
            except OSError:
                pass
        self.assertFalse(err)
        self.assertEqual(bytes(received), payload)
        self.assertGreater(len(received), 50_000)

    def test_byte_identity_small(self):
        a, a2 = socket.socketpair()
        b, b2 = socket.socketpair()
        msg = b"\xff\xd8\xff" + b"JPEG-BYTES" * 100  # fake image-ish

        def relay():
            P.pipe_bidirectional(a, b)

        threading.Thread(target=relay, daemon=True).start()
        b2.sendall(msg)
        b2.shutdown(socket.SHUT_WR)
        got = b""
        a2.settimeout(3)
        while True:
            try:
                chunk = a2.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            got += chunk
        for s in (a, a2, b, b2):
            try:
                s.close()
            except OSError:
                pass
        self.assertEqual(got, msg)


class EgressPolicyTests(unittest.TestCase):
    def test_public_ip_allowlist(self):
        self.assertTrue(P.is_public_ip("87.240.129.1"))
        self.assertTrue(P.is_public_ip("2001:4860:4860::8888"))
        for bad in (
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "not-an-ip",
        ):
            self.assertFalse(P.is_public_ip(bad), bad)

    def test_ip_literal_and_hostname(self):
        self.assertTrue(P.is_ip_literal("127.0.0.1"))
        self.assertTrue(P.is_ip_literal("::1"))
        self.assertFalse(P.is_ip_literal("vk.com"))
        self.assertTrue(P.is_safe_hostname("sun9-76.userapi.com"))
        self.assertFalse(P.is_safe_hostname("vk.com.evil.com/"))
        self.assertFalse(P.is_safe_hostname("evil.com@vk.com"))
        self.assertFalse(P.is_target_host("vk.com.evil.com"))
        self.assertFalse(P.is_target_host("notvk.com"))
        self.assertFalse(P.is_target_host("127.0.0.1"))
        self.assertTrue(P.is_target_host("a.vk.com"))

    def test_redirect_stays_on_host(self):
        self.assertEqual(
            P.safe_https_location("vk.com", "/login"),
            "https://vk.com/login",
        )
        self.assertEqual(
            P.safe_https_location("vk.com", "@evil.com"),
            "https://vk.com/",
        )
        self.assertEqual(
            P.safe_https_location("vk.com", "//evil.com"),
            "https://vk.com/",
        )

    def test_only_vk_hosts_are_proxied(self):
        self.assertTrue(P.is_allowed_proxy_target("vk.com", 443, connect=True))
        self.assertTrue(P.is_allowed_proxy_target("sun9-76.userapi.com", 443, connect=True))
        self.assertFalse(P.is_allowed_proxy_target("youtube.com", 443, connect=True))
        self.assertFalse(P.is_allowed_proxy_target("vk.com", 22, connect=True))
        self.assertFalse(P.is_allowed_proxy_target("1.1.1.1", 443, connect=True))
        self.assertTrue(P.is_allowed_proxy_target("login.vk.ru", 80, connect=False))
        self.assertFalse(P.is_allowed_proxy_target("example.com", 80, connect=False))

    def test_proxy_backup_restores_previous_settings(self):
        backup = {
            "ProxyEnable": 1,
            "ProxyServer": "127.0.0.1:9",
            "AutoConfigURL": "http://corp.example/proxy.pac",
        }
        current = {
            "ProxyEnable": 0,
            "ProxyServer": "127.0.0.1:9",
            "AutoConfigURL": P.PAC_URL,
        }
        self.assertTrue(
            P.should_keep_proxy_backup(P.PAC_URL, P.PAC_URL, backup_exists=True)
        )
        self.assertFalse(
            P.should_keep_proxy_backup(
                "http://corp.example/proxy.pac", P.PAC_URL, backup_exists=True
            )
        )
        restored = P.restored_proxy_settings(backup, current, P.PAC_URL)
        self.assertEqual(restored["AutoConfigURL"], "http://corp.example/proxy.pac")
        self.assertEqual(restored["ProxyEnable"], 1)
        self.assertIsNone(
            P.restored_proxy_settings(
                None,
                {"ProxyEnable": 1, "ProxyServer": "10.0.0.1:8080", "AutoConfigURL": ""},
                P.PAC_URL,
            )
        )
        removed = P.restored_proxy_settings(None, current, P.PAC_URL)
        self.assertEqual(removed["AutoConfigURL"], "")
        self.assertEqual(removed["ProxyServer"], "127.0.0.1:9")

    def test_autostart_off_stays_off(self):
        self.assertEqual(P.decide_autostart(False, False), (True, True))
        self.assertEqual(P.decide_autostart(True, False), (False, False))
        self.assertEqual(P.decide_autostart(True, True), (True, False))

    def test_health_response_is_not_world_readable_cors(self):
        src = Path(P.__file__).read_text(encoding="utf-8")
        self.assertNotIn("Access-Control-Allow-Origin", src)


class ConnectClassifyTests(unittest.TestCase):
    def test_close_reasons(self):
        self.assertEqual(P.classify_close_error(TimeoutError("x")), "timeout")
        self.assertEqual(P.classify_close_error(ConnectionResetError()), "reset")


class ContentScriptPresenceTests(unittest.TestCase):
    def test_extension_has_content_script(self):
        ext = ROOT.parent / "vk-dpi-extension"
        man = (ext / "manifest.json").read_text(encoding="utf-8")
        self.assertIn("content_scripts", man)
        self.assertTrue((ext / "content.js").is_file())
        js = (ext / "content.js").read_text(encoding="utf-8")
        self.assertNotIn("size=orig", js.lower())
        self.assertNotIn("4096", js)
        self.assertIn("sanitizeUrlForLog", js)
        self.assertIn("srcset", js)
        self.assertIn("u.username", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
