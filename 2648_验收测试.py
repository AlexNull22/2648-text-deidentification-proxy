"""文本脱敏代理的真实业务验收；全部数据自造，映射库和HTTP服务均为本机临时资源。"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
import copy
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet


BASE = Path(__file__).resolve().parent


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, BASE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


vault_module = load_module("redaction_vault_2648", "2648_加密映射库.py")
KINDS = ("PERSON", "CORP", "EMAIL", "PHONE", "LOCATION", "POSTAL", "CARD")


class EncryptedVaultAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="2648_映射验收_")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.path = self.root / "2648_加密映射.sqlite"
        self.key = Fernet.generate_key()
        self.vault = vault_module.Vault(self.path, self.key)

    def test_all_seven_types_have_independent_monotonic_counters(self):
        self.assertEqual(self.vault.stats("session_a"), {kind: 0 for kind in KINDS})
        for kind in KINDS:
            self.assertEqual(self.vault.token_for("session_a", kind, "Synthetic " + kind), f"[{kind}_01]")
            self.assertEqual(self.vault.token_for("session_a", kind, "Another " + kind), f"[{kind}_02]")
        self.assertEqual(self.vault.stats("session_a"), {kind: 2 for kind in KINDS})

    def test_exact_identity_is_reused_without_case_or_whitespace_normalization(self):
        values = ["Alice Example", "alice example", " Alice Example "]
        tokens = [self.vault.token_for("exact", "PERSON", value) for value in values]
        self.assertEqual(tokens, ["[PERSON_01]", "[PERSON_02]", "[PERSON_03]"])
        self.assertEqual(self.vault.token_for("exact", "PERSON", values[0]), tokens[0])
        self.assertEqual(self.vault.stats("exact")["PERSON"], 3)
        for value, token in zip(values, tokens):
            self.assertEqual(self.vault.restore_text("exact", token), value)

    def test_session_mappings_are_isolated_even_when_token_literals_repeat(self):
        first = self.vault.token_for("session_a", "PERSON", "Alice Synthetic")
        second = self.vault.token_for("session_b", "PERSON", "Robert Synthetic")
        self.assertEqual(first, "[PERSON_01]")
        self.assertEqual(second, "[PERSON_01]")
        self.assertEqual(self.vault.restore_text("session_a", first), "Alice Synthetic")
        self.assertEqual(self.vault.restore_text("session_b", second), "Robert Synthetic")
        self.assertEqual(self.vault.stats("unrelated"), {kind: 0 for kind in KINDS})
        with self.assertRaises(vault_module.VaultError):
            self.vault.restore_text("unrelated", first)

    def test_mapping_persists_and_supports_string_fernet_keys(self):
        token = self.vault.token_for("persist", "EMAIL", "synthetic.person@example.invalid")
        reopened = vault_module.Vault(self.path, self.key.decode("ascii"))
        self.assertEqual(reopened.token_for("persist", "EMAIL", "synthetic.person@example.invalid"), token)
        self.assertEqual(reopened.restore_text("persist", "Contact " + token), "Contact synthetic.person@example.invalid")
        self.assertEqual(reopened.stats("persist")["EMAIL"], 1)

    def test_wrong_key_fails_without_corrupting_existing_mapping_or_leaking_secrets(self):
        sensitive = "UNIQUE-SYNTHETIC-NAME-2648-Secret"
        token = self.vault.token_for("keys", "PERSON", sensitive)
        wrong_key = Fernet.generate_key()
        with self.assertRaises(vault_module.VaultError) as caught:
            vault_module.Vault(self.path, wrong_key)
        self.assertNotIn(sensitive, str(caught.exception))
        self.assertNotIn(wrong_key.decode("ascii"), str(caught.exception))
        reopened = vault_module.Vault(self.path, self.key)
        self.assertEqual(reopened.restore_text("keys", token), sensitive)

    def test_sqlite_and_sidecar_files_do_not_contain_plaintext_values_or_the_key(self):
        values = ["UNIQUE-PII-2648-Alice-Synthetic", "private2648@example.invalid", "合成隐私姓名二六四八"]
        for kind, value in zip(("PERSON", "EMAIL", "LOCATION"), values):
            self.vault.token_for("encrypted", kind, value)
        with closing(sqlite3.connect(self.path)) as connection:
            dump = "\n".join(connection.iterdump())
        for value in values:
            self.assertNotIn(value, dump)
        for path in self.root.iterdir():
            if path.is_file():
                raw = path.read_bytes()
                for value in values:
                    self.assertNotIn(value.encode("utf-8"), raw)
                self.assertNotIn(self.key, raw)

    def test_unknown_locked_token_is_rejected_without_partial_restore_or_raw_error(self):
        secret = "Synthetic Person 2648"
        known = self.vault.token_for("restore", "PERSON", secret)
        before = self.vault.stats("restore")
        with self.assertRaises(vault_module.VaultError) as caught:
            self.vault.restore_text("restore", known + " and [PERSON_99]")
        self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(self.vault.stats("restore"), before)
        with self.assertRaises(vault_module.VaultError):
            self.vault.restore_text("restore", "Literal [UNKNOWN_01]")

    def test_invalid_session_ids_and_sql_injection_attempts_are_rejected(self):
        invalid = ["", " ", "中文会话", "a" * 81, "../session", "x'; DROP TABLE mappings;--", None, 12, True]
        for session in invalid:
            with self.subTest(session=session):
                with self.assertRaises(vault_module.VaultError):
                    self.vault.token_for(session, "PERSON", "Synthetic Person")
        self.assertEqual(self.vault.token_for("safe_session-1", "PERSON", "Synthetic Person"), "[PERSON_01]")

    def test_invalid_kinds_cannot_be_interpolated_into_sql_or_token_names(self):
        for kind in ("person", "UNKNOWN", "PERSON]; DROP TABLE x;--", "", None, 12):
            with self.subTest(kind=kind):
                with self.assertRaises(vault_module.VaultError):
                    self.vault.token_for("safe", kind, "Synthetic Person")
        self.assertEqual(self.vault.stats("safe"), {kind: 0 for kind in KINDS})

    def test_values_require_nonempty_strings_and_sql_looking_data_stays_literal(self):
        for value in ("", None, 12, True, b"bytes"):
            with self.subTest(value=value):
                with self.assertRaises(vault_module.VaultError):
                    self.vault.token_for("values", "PERSON", value)
        value = "Synthetic'); DROP TABLE mappings;--"
        token = self.vault.token_for("values", "PERSON", value)
        self.assertEqual(self.vault.restore_text("values", token), value)
        self.assertEqual(self.vault.stats("values")["PERSON"], 1)

    def test_counters_remain_unambiguous_beyond_two_digits(self):
        tokens = [self.vault.token_for("many", "PERSON", f"Synthetic Person {index}") for index in range(1, 106)]
        self.assertEqual((tokens[0], tokens[98], tokens[99], tokens[-1]), ("[PERSON_01]", "[PERSON_99]", "[PERSON_100]", "[PERSON_105]"))
        self.assertEqual(len(set(tokens)), 105)
        self.assertEqual(self.vault.restore_text("many", "[PERSON_100] / [PERSON_01]"), "Synthetic Person 100 / Synthetic Person 1")

    def test_concurrent_duplicate_and_distinct_identities_are_bijective(self):
        values = [f"Synthetic Concurrent Person {number:03d}" for number in range(40)]
        tasks = values * 4
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.vault.token_for, "threads", "PERSON", value) for value in tasks]
            pairs = [(value, future.result(timeout=30)) for value, future in zip(tasks, futures)]
        by_value, by_token = {}, {}
        for value, token in pairs:
            by_value.setdefault(value, set()).add(token)
            by_token.setdefault(token, set()).add(value)
        self.assertEqual(len(by_value), 40)
        self.assertEqual(len(by_token), 40)
        self.assertTrue(all(len(tokens) == 1 for tokens in by_value.values()))
        self.assertTrue(all(len(originals) == 1 for originals in by_token.values()))
        self.assertEqual(self.vault.stats("threads")["PERSON"], 40)
        for value, tokens in by_value.items():
            self.assertEqual(self.vault.restore_text("threads", next(iter(tokens))), value)

    def test_malformed_keys_are_rejected_as_domain_errors(self):
        for index, key in enumerate((b"not-a-fernet-key", "", "not-base64", None, 123)):
            with self.subTest(index=index):
                with self.assertRaises(vault_module.VaultError):
                    vault_module.Vault(self.root / f"2648_无效密钥_{index}.sqlite", key)

    def test_swapping_database_ordinals_is_detected_before_restore_or_identity_reuse(self):
        values = ["Synthetic Bound Alice", "Synthetic Bound Robert", "Synthetic Bound Carol"]
        for value in values:
            self.vault.token_for("binding", "PERSON", value)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE vault_mappings SET ordinal=ordinal+10 WHERE session_id=? AND kind=?", ("binding", "PERSON"))
            connection.execute("UPDATE vault_mappings SET ordinal=CASE ordinal WHEN 11 THEN 3 WHEN 12 THEN 1 WHEN 13 THEN 2 END WHERE session_id=? AND kind=?", ("binding", "PERSON"))
            connection.commit()
        for token in ("[PERSON_01]", "[PERSON_02]", "[PERSON_03]"):
            with self.subTest(token=token):
                with self.assertRaises(vault_module.VaultError) as caught:
                    self.vault.restore_text("binding", token)
                self.assertTrue(all(value not in str(caught.exception) for value in values))
        for value in values:
            with self.assertRaises(vault_module.VaultError) as caught:
                self.vault.token_for("binding", "PERSON", value)
            self.assertNotIn(value, str(caught.exception))


class LocalSink:
    """只接受本机测试POST；记录真实接收到的字节，默认不打印日志。"""
    def __init__(self, status=200, redirect=None):
        self.received = []
        self.status = status
        self.redirect = redirect
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                fixture.received.append({"path": self.path, "body": body, "content_type": self.headers.get("Content-Type")})
                self.send_response(fixture.status)
                if fixture.redirect:
                    self.send_header("Location", fixture.redirect)
                response = b'{"synthetic_sink":true}'
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class RedactionPipelineAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = load_module("redaction_pipeline_2648", "2648_脱敏核心.py")
        # No NER stub: these assertions exercise the installed English spaCy model.
        cls.detector = cls.core.Detector(model_name="en_core_web_sm")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="2648_流水线验收_")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.vault = vault_module.Vault(self.root / "2648_映射.sqlite", Fernet.generate_key())
        self.pipeline = self.core.Pipeline(self.vault, self.detector)
        self.queue = self.root / "2648_异常队列"

    @staticmethod
    def payload():
        return {"Alice Johnson": {
            "statement": "Alice Johnson works at Microsoft in London.",
            "contacts": {"email": "alice.johnson@example.invalid", "phone": "+1 415 555 0134"},
            "billing": ["4111 1111 1111 1111", "94105"], "city": "Paris"},
            "count": 2, "price": 1.25, "enabled": True, "empty": None, "notes": ["", "Plain synthetic note."]}

    @staticmethod
    def originals():
        return ["Alice Johnson", "Microsoft", "London", "alice.johnson@example.invalid", "+1 415 555 0134", "4111 1111 1111 1111", "94105", "Paris"]

    def assert_no_originals(self, value):
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        for original in self.originals():
            self.assertNotIn(original, text)

    def sink(self, status=200, redirect=None):
        sink = LocalSink(status, redirect)
        self.addCleanup(sink.close)
        return sink

    def api_server(self, sink=None):
        server = self.core.serve(self.pipeline, port=0, forward_url=None if sink is None else sink.url + "/2648_sink", queue_dir=self.queue)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        self.addCleanup(close)
        return server

    @staticmethod
    def request(server, path, value, headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8")
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        with closing(HTTPConnection("127.0.0.1", server.server_port, timeout=10)) as connection:
            connection.request("POST", path, body=body, headers=request_headers)
            with closing(connection.getresponse()) as response:
                return response.status, response.read()

    def test_real_english_model_detects_person_company_and_locations(self):
        text = "Alice Johnson works at Microsoft in London. Bob Smith visited Paris."
        found = {(item["kind"], item["value"]) for item in self.detector.detect(text)}
        self.assertTrue({("PERSON", "Alice Johnson"), ("CORP", "Microsoft"), ("LOCATION", "London"), ("PERSON", "Bob Smith"), ("LOCATION", "Paris")} <= found)
        self.assertEqual(self.detector.model_name, "en_core_web_sm")
        self.assertIn("ner", self.detector.nlp.pipe_names)

    def test_structured_matches_have_complete_nonoverlapping_priority_spans(self):
        text = "Email alice.johnson@example.invalid; phone +1 415 555 0134; card 4111 1111 1111 1111; ZIP 94105-1234."
        spans = self.detector.detect(text)
        required = {("EMAIL", "alice.johnson@example.invalid"), ("PHONE", "+1 415 555 0134"), ("CARD", "4111 1111 1111 1111"), ("POSTAL", "94105-1234")}
        self.assertTrue(required <= {(item["kind"], item["value"]) for item in spans})
        previous_end = 0
        for item in spans:
            self.assertGreaterEqual(item["start"], previous_end)
            self.assertEqual(text[item["start"]:item["end"]], item["value"])
            previous_end = item["end"]

    def test_common_phone_formats_are_fully_redacted_and_reversible(self):
        values = ["+1 415 555 0134", "+1 (415) 555-0134", "(415) 555-0134", "4155550134", "+44 20 7946 0958"]
        for index, value in enumerate(values):
            with self.subTest(value=value):
                result = self.pipeline.scrub(f"phone_{index}", "Call " + value + ".")
                self.assertNotIn(value, result["payload"])
                self.assertIn("[PHONE_01]", result["payload"])
                self.assertEqual(self.pipeline.restore(f"phone_{index}", result["payload"]), "Call " + value + ".")

    def test_nested_json_keys_and_values_roundtrip_exactly_without_mutating_input(self):
        payload = self.payload()
        before = copy.deepcopy(payload)
        result = self.pipeline.scrub("nested", payload)
        self.assertEqual(payload, before)
        self.assert_no_originals(result["payload"])
        self.assertTrue(all(result["counts"].get(kind, 0) > 0 for kind in KINDS))
        self.assertNotIn("Alice Johnson", result["payload"])
        self.assertEqual(self.pipeline.restore("nested", result["payload"]), payload)

    def test_repeated_identity_reuses_token_and_sessions_restore_their_own_identity(self):
        text = "Alice Johnson visited London. Alice Johnson works at Microsoft."
        first = self.pipeline.scrub("same", text)
        second = self.pipeline.scrub("same", text)
        self.assertEqual(first, second)
        self.assertEqual(self.vault.stats("same")["PERSON"], 1)
        alice = self.pipeline.scrub("alice_session", "Alice Johnson.")["payload"]
        bob = self.pipeline.scrub("bob_session", "Bob Smith.")["payload"]
        self.assertIn("[PERSON_01]", alice)
        self.assertIn("[PERSON_01]", bob)
        self.assertEqual(self.pipeline.restore("alice_session", alice), "Alice Johnson.")
        self.assertEqual(self.pipeline.restore("bob_session", bob), "Bob Smith.")

    def test_preexisting_tokenlike_keys_or_values_are_rejected_before_mapping(self):
        cases = ["Hello [PERSON_01]", {"[EMAIL_01]": "ordinary"}, {"text": ["[UNKNOWN_01]"]}]
        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                session = f"reserved_{index}"
                with self.assertRaises(self.core.ProcessingError):
                    self.pipeline.scrub(session, payload)
                self.assertEqual(self.vault.stats(session), {kind: 0 for kind in KINDS})

    def test_large_nonstring_numbers_nonfinite_values_and_invalid_json_types_fail_closed(self):
        cases = [12345678, -12345678, 1e20, -1e20, 1e4, 12345, float("nan"), float("inf"), b"not json", {1: "integer key"}]
        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(self.core.ProcessingError):
                    self.pipeline.scrub(f"invalid_{index}", payload)
        accepted = {"count": 123, "ratio": 1.25, "enabled": True, "empty": None}
        self.assertEqual(self.pipeline.scrub("small_numbers", accepted)["payload"], accepted)

    def test_payload_size_depth_and_node_limits_reject_without_vault_changes(self):
        deep = "leaf"
        for _ in range(20):
            deep = [deep]
        for index, payload in enumerate(("x" * 100001, deep, [0] * 2001)):
            with self.subTest(index=index):
                with self.assertRaises(self.core.ProcessingError):
                    self.pipeline.scrub(f"limits_{index}", payload)
                self.assertEqual(self.vault.stats(f"limits_{index}"), {kind: 0 for kind in KINDS})

    def test_real_http_outbox_receives_only_sanitized_json_and_exact_roundtrip(self):
        sink = self.sink()
        payload = self.payload()
        logs = io.StringIO()
        with redirect_stdout(logs), redirect_stderr(logs):
            result = self.pipeline.forward("delivered", payload, sink.url + "/2648_sink", self.queue)
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(len(sink.received), 1)
        received = json.loads(sink.received[0]["body"])
        self.assertEqual(received["session"], "delivered")
        self.assertEqual(received["payload"], result["payload"])
        self.assert_no_originals(received)
        self.assert_no_originals(logs.getvalue())
        self.assertEqual(self.pipeline.restore("delivered", received["payload"]), payload)
        self.assertFalse(self.queue.exists())

    def test_downstream_failure_queue_contains_only_sanitized_payload(self):
        sink = self.sink(status=503)
        logs = io.StringIO()
        with redirect_stdout(logs), redirect_stderr(logs):
            result = self.pipeline.forward("retry", self.payload(), sink.url + "/2648_sink", self.queue)
        self.assertEqual(result["status"], "queued")
        queued_file = self.queue / result["queue_file"]
        self.assertEqual(queued_file.parent, self.queue)
        self.assertTrue(queued_file.name.startswith("2648_"))
        queued = json.loads(queued_file.read_text(encoding="utf-8"))
        self.assertEqual(queued["payload"], result["payload"])
        self.assertEqual(queued["reason"], "downstream_unavailable")
        self.assert_no_originals(queued_file.read_text(encoding="utf-8"))
        self.assert_no_originals(sink.received[0]["body"].decode("utf-8"))
        self.assert_no_originals(logs.getvalue())
        self.assertEqual(self.pipeline.restore("retry", queued["payload"]), self.payload())

    def test_downstream_redirect_is_not_followed_and_queues_sanitized_payload(self):
        other = self.sink()
        sink = self.sink(status=302, redirect=other.url + "/2648_forbidden")
        result = self.pipeline.forward("redirect", self.payload(), sink.url + "/2648_sink", self.queue)
        self.assertEqual(result["status"], "queued")
        self.assertEqual(other.received, [])
        self.assert_no_originals((self.queue / result["queue_file"]).read_text(encoding="utf-8"))

    def test_nonlocal_credential_query_and_fragment_endpoints_are_rejected_without_send_or_queue(self):
        sink = self.sink()
        urls = ["http://example.invalid:8080/sink", "http://localhost:8080/sink", "https://127.0.0.1:8080/sink",
                "http://user:secret@127.0.0.1:8080/sink", sink.url + "/sink?token=secret", sink.url + "/sink#fragment", "http://127.0.0.1/sink"]
        for index, url in enumerate(urls):
            with self.subTest(url=url):
                with self.assertRaises(self.core.ProcessingError):
                    self.pipeline.forward(f"endpoint_{index}", self.payload(), url, self.queue)
        self.assertEqual(sink.received, [])
        self.assertFalse(self.queue.exists())

    def test_ner_runtime_failure_stops_before_send_queue_or_mapping_and_hides_raw_error(self):
        sink = self.sink()
        raw_error = "Synthetic private alice.johnson@example.invalid should never be logged"
        logs = io.StringIO()
        # Fault injection tests failure handling; entity acceptance above uses the real model.
        with patch.object(self.detector, "nlp", side_effect=RuntimeError(raw_error)), redirect_stdout(logs), redirect_stderr(logs):
            with self.assertRaises(self.core.ProcessingError) as caught:
                self.pipeline.forward("model_failure", self.payload(), sink.url + "/2648_sink", self.queue)
        self.assertNotIn(raw_error, str(caught.exception))
        self.assertNotIn(raw_error, logs.getvalue())
        self.assertEqual(sink.received, [])
        self.assertFalse(self.queue.exists())
        self.assertEqual(self.vault.stats("model_failure"), {kind: 0 for kind in KINDS})

    def test_api_scrub_and_restore_use_real_model_and_restore_exact_nested_json(self):
        server = self.api_server()
        original = self.payload()
        status, body = self.request(server, "/scrub", {"session": "api_ok", "payload": original})
        self.assertEqual(status, 200)
        scrubbed = json.loads(body)
        self.assert_no_originals(scrubbed)
        allowed_origin = f"http://127.0.0.1:{server.server_port}"
        restored_status, restored_body = self.request(server, "/restore", {"session": "api_ok", "payload": scrubbed["payload"]}, {"Origin": allowed_origin})
        self.assertEqual(restored_status, 200)
        self.assertEqual(json.loads(restored_body)["payload"], original)

    def test_api_rejects_host_origin_and_content_type_without_forwarding_or_raw_errors(self):
        sink = self.sink()
        server = self.api_server(sink)
        invalid_headers = [{"Host": "evil.invalid"}, {"Origin": "https://evil.invalid"}, {"Content-Type": "text/plain"}]
        logs = io.StringIO()
        with redirect_stdout(logs), redirect_stderr(logs):
            for headers in invalid_headers:
                with self.subTest(headers=headers):
                    status, body = self.request(server, "/forward", {"session": "api_guard", "payload": self.payload()}, headers)
                    self.assertEqual(status, 400)
                    self.assertEqual(json.loads(body)["error"], "request_rejected")
                    self.assert_no_originals(body.decode("utf-8"))
        self.assert_no_originals(logs.getvalue())
        self.assertEqual(sink.received, [])
        self.assertFalse(self.queue.exists())
        self.assertEqual(self.vault.stats("api_guard"), {kind: 0 for kind in KINDS})

    def test_api_byte_limit_is_checked_before_processing_multibyte_payload(self):
        server = self.api_server()
        request = {"session": "api_bytes", "payload": "界" * 40000}
        raw = json.dumps(request, ensure_ascii=False).encode("utf-8")
        self.assertGreater(len(raw), 100000)
        status, body = self.request(server, "/scrub", raw)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "request_rejected")
        self.assertEqual(self.vault.stats("api_bytes"), {kind: 0 for kind in KINDS})

    def test_api_duplicate_keys_and_nan_are_rejected_before_forwarding(self):
        sink = self.sink()
        server = self.api_server(sink)
        requests = [b'{"session":"strict_api","payload":{"name":"Alice Johnson","name":"Bob Smith"}}',
                    b'{"session":"strict_api","payload":{"amount":NaN}}']
        for raw in requests:
            with self.subTest(raw=raw):
                status, body = self.request(server, "/forward", raw)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body)["error"], "request_rejected")
                self.assert_no_originals(body.decode("utf-8"))
        self.assertEqual(sink.received, [])
        self.assertFalse(self.queue.exists())
        self.assertEqual(self.vault.stats("strict_api"), {kind: 0 for kind in KINDS})

    def cli_files(self):
        source = self.root / "2648_命令行输入.json"
        key_file = self.root / "2648_命令行密钥.key"
        source.write_text(json.dumps(self.payload(), ensure_ascii=False), encoding="utf-8")
        key_file.write_bytes(Fernet.generate_key())
        return source, key_file

    def run_cli(self, source, output, vault, key_file, sink=None):
        command = [sys.executable, "-B", str(BASE / "2648_脱敏核心.py"), "--input", str(source),
                   "--output", str(output), "--vault", str(vault), "--key-file", str(key_file),
                   "--session", "cli_synthetic", "--queue-dir", str(self.queue)]
        if sink:
            command.extend(["--forward-url", sink.url + "/2648_sink"])
        completed = subprocess.run(command, cwd=self.root, capture_output=True, timeout=30)
        self.assert_no_originals((completed.stdout + completed.stderr).decode("utf-8", errors="replace"))
        return completed

    def test_cli_all_input_output_vault_key_path_aliases_are_rejected_without_file_changes(self):
        source, key_file = self.cli_files()
        default_output = self.root / "2648_命令行输出.json"
        default_vault = self.root / "2648_命令行映射.sqlite"
        cases = [(source, source, default_vault, key_file),
                 (source, key_file, default_vault, key_file),
                 (source, default_vault, default_vault, key_file),
                 (source, default_output, source, key_file),
                 (source, default_output, default_vault, source),
                 (source, default_output, key_file, key_file)]
        before = {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}
        for index, paths in enumerate(cases):
            with self.subTest(index=index):
                self.assertNotEqual(self.run_cli(*paths).returncode, 0)
                self.assertEqual({path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}, before)
        self.assertFalse(self.queue.exists())

    def test_cli_existing_output_blocks_forwarding_and_preserves_original_files(self):
        source, key_file = self.cli_files()
        output = self.root / "2648_已有输出.json"
        output.write_bytes(b"keep existing result")
        vault = self.root / "2648_尚未创建映射.sqlite"
        before_source, before_key = source.read_bytes(), key_file.read_bytes()
        sink = self.sink()
        completed = self.run_cli(source, output, vault, key_file, sink)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output.read_bytes(), b"keep existing result")
        self.assertEqual(source.read_bytes(), before_source)
        self.assertEqual(key_file.read_bytes(), before_key)
        self.assertFalse(vault.exists())
        self.assertEqual(sink.received, [])
        self.assertFalse(self.queue.exists())

    def test_cli_duplicate_keys_and_nan_leave_no_output_and_do_not_forward(self):
        source, key_file = self.cli_files()
        sink = self.sink()
        cases = ['{"name":"Alice Johnson","name":"Bob Smith"}', '{"amount":NaN}']
        for index, raw in enumerate(cases):
            with self.subTest(index=index):
                source.write_text(raw, encoding="utf-8")
                output = self.root / f"2648_非法输入输出_{index}.json"
                vault = self.root / f"2648_非法输入映射_{index}.sqlite"
                completed = self.run_cli(source, output, vault, key_file, sink)
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(output.exists())
                self.assertEqual(source.read_text(encoding="utf-8"), raw)
        self.assertEqual(sink.received, [])
        self.assertFalse(self.queue.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
