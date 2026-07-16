from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock


LAB3 = Path(__file__).resolve().parents[1]
REPOSITORY = LAB3.parent
if str(LAB3) not in sys.path:
    sys.path.insert(0, str(LAB3))

from SampleNetworkClient import (  # noqa: E402
    AuthenticationError,
    SimpleNetworkClient,
)
from SampleNetworkServer import SmartNetworkThermometer  # noqa: E402
from secure_transport import (  # noqa: E402
    PROTOCOL_VERSION,
    ConfigurationError,
    PacketError,
    decrypt_packet,
    encrypt_packet,
)


class FakeTemperatureSource:
    def __init__(self, temperature: float = 310.15) -> None:
        self.temperature = temperature
        self.calls = 0

    def getTemperature(self) -> float:
        self.calls += 1
        return self.temperature


class FakeClock:
    def __init__(self, initial: float | None = None) -> None:
        self.value = time.time() if initial is None else initial

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class CodingTask2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.password = "unit-test-password-not-a-secret"
        self.key = secrets.token_bytes(32)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "INCUBATOR_AUTH_PASSWORD": self.password,
                "INCUBATOR_TRANSPORT_KEY": base64.b64encode(self.key).decode("ascii"),
            },
            clear=False,
        )
        self.environment.start()
        self.servers: list[SmartNetworkThermometer] = []
        self.clients: list[SimpleNetworkClient] = []

    def tearDown(self) -> None:
        for client in self.clients:
            client.close()
        for server in self.servers:
            server.close()
        for server in self.servers:
            if server.is_alive():
                server.join(timeout=1)
        self.environment.stop()

    def make_server(self, **options) -> SmartNetworkThermometer:
        server = SmartNetworkThermometer(
            FakeTemperatureSource(), 0.01, 0, **options
        )
        self.servers.append(server)
        return server

    def start_server(self, **options) -> SmartNetworkThermometer:
        server = self.make_server(**options)
        server.start()
        return server

    def make_client(self, server: SmartNetworkThermometer) -> SimpleNetworkClient:
        client = SimpleNetworkClient(server.port, server.port, timeout=1)
        self.clients.append(client)
        return client

    def direct_request(
        self,
        server: SmartNetworkThermometer,
        address: tuple[str, int],
        request_type: str,
        **fields,
    ) -> tuple[dict, bytes]:
        request = {
            "version": PROTOCOL_VERSION,
            "type": request_type,
            "request_id": secrets.token_urlsafe(16),
            "timestamp": int(server._time()),
            **fields,
        }
        packet = encrypt_packet(request, self.key)
        response_packet = server.handle_datagram(packet, address)
        return decrypt_packet(response_packet, self.key), packet

    def direct_authenticate(
        self,
        server: SmartNetworkThermometer,
        address: tuple[str, int],
        password: str | None = None,
    ) -> str:
        response, _packet = self.direct_request(
            server,
            address,
            "AUTH",
            password=self.password if password is None else password,
        )
        self.assertTrue(response["ok"])
        return response["token"]

    # Configuration and source-code controls

    def test_01_missing_auth_password_fails_closed(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"INCUBATOR_TRANSPORT_KEY": base64.b64encode(self.key).decode("ascii")},
            clear=True,
        ):
            with self.assertRaisesRegex(ConfigurationError, "INCUBATOR_AUTH_PASSWORD"):
                SmartNetworkThermometer(FakeTemperatureSource(), 0.01, 0)

    def test_02_missing_transport_key_fails_closed(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"INCUBATOR_AUTH_PASSWORD": self.password},
            clear=True,
        ):
            with self.assertRaisesRegex(ConfigurationError, "INCUBATOR_TRANSPORT_KEY"):
                SmartNetworkThermometer(FakeTemperatureSource(), 0.01, 0)

    def test_03_malformed_transport_key_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {"INCUBATOR_TRANSPORT_KEY": "not base64!!!"}):
            with self.assertRaisesRegex(ConfigurationError, "valid Base64"):
                SmartNetworkThermometer(FakeTemperatureSource(), 0.01, 0)

    def test_04_incorrect_transport_key_length_fails_closed(self) -> None:
        short_key = base64.b64encode(b"short").decode("ascii")
        with mock.patch.dict(os.environ, {"INCUBATOR_TRANSPORT_KEY": short_key}):
            with self.assertRaisesRegex(ConfigurationError, "exactly 32 bytes"):
                SmartNetworkThermometer(FakeTemperatureSource(), 0.01, 0)

    def test_05_original_password_absent_from_active_sources(self) -> None:
        preserved_server = (LAB3 / "copy" / "SampleNetworkServer.py").read_text(
            encoding="utf-8"
        )
        match = re.search(r'cs\[1\]\s*==\s*"([^"]+)"', preserved_server)
        self.assertIsNotNone(match, "Could not identify the preserved vulnerable password")
        original_password = match.group(1)
        checked_suffixes = {".py", ".html", ".md", ".txt", ".example"}
        offenders = []
        for path in LAB3.rglob("*"):
            if not path.is_file() or "copy" in path.parts or path.suffix not in checked_suffixes:
                continue
            if original_password in path.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(path.relative_to(LAB3)))
        self.assertEqual([], offenders)

    def test_06_no_insecure_token_generation_or_plaintext_parser_in_active_python(self) -> None:
        active = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in LAB3.rglob("*.py")
            if "copy" not in path.parts
        )
        forbidden_fragments = (
            "random" + ".choice",
            "split(" + "';'" + ")",
            "split(" + '";"' + ")",
            'b"AUTH ' + "%s",
        )
        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, active)

    # Authentication and encrypted transport

    def test_07_correct_password_authenticates_over_udp(self) -> None:
        server = self.start_server()
        client = self.make_client(server)
        self.assertTrue(client.authenticate(server.port, self.password))

    def test_08_incorrect_password_fails(self) -> None:
        server = self.start_server()
        client = self.make_client(server)
        with self.assertRaises(AuthenticationError):
            client.authenticate(server.port, "incorrect-test-password")
        self.assertEqual(0, server.active_session_count)

    def test_09_plaintext_auth_packet_is_rejected(self) -> None:
        server = self.make_server()
        response_packet = server.handle_datagram(b"AUTH plaintext", ("127.0.0.1", 41001))
        response = decrypt_packet(response_packet, self.key)
        self.assertFalse(response["ok"])
        self.assertEqual(0, server.active_session_count)

    def test_10_plaintext_token_command_is_rejected(self) -> None:
        server = self.make_server()
        response_packet = server.handle_datagram(
            b"plaintext-token;GET_TEMP", ("127.0.0.1", 41002)
        )
        response = decrypt_packet(response_packet, self.key)
        self.assertFalse(response["ok"])
        self.assertEqual("K", server.deg)

    def test_11_valid_aes_gcm_encrypted_authentication_works(self) -> None:
        server = self.make_server()
        response, packet = self.direct_request(
            server, ("127.0.0.1", 41003), "AUTH", password=self.password
        )
        envelope = json.loads(packet.decode("ascii"))
        self.assertEqual(
            {"version", "nonce", "ciphertext", "tag"}, set(envelope)
        )
        self.assertTrue(response["ok"])

    def test_12_valid_encrypted_get_temperature_works(self) -> None:
        server = self.start_server()
        client = self.make_client(server)
        token = client.authenticate(server.port, self.password)
        self.assertAlmostEqual(310.15, client.getTemperatureFromPort(server.port, token))

    def test_13_modified_ciphertext_is_rejected(self) -> None:
        server = self.make_server()
        request = {
            "version": PROTOCOL_VERSION,
            "type": "AUTH",
            "request_id": secrets.token_urlsafe(16),
            "timestamp": int(time.time()),
            "password": self.password,
        }
        envelope = json.loads(encrypt_packet(request, self.key).decode("ascii"))
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        ciphertext[0] ^= 1
        envelope["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        tampered = json.dumps(envelope, separators=(",", ":")).encode("ascii")
        response = decrypt_packet(
            server.handle_datagram(tampered, ("127.0.0.1", 41004)), self.key
        )
        self.assertFalse(response["ok"])
        self.assertEqual(0, server.active_session_count)

    def test_14_modified_gcm_tag_is_rejected(self) -> None:
        server = self.make_server()
        request = {
            "version": PROTOCOL_VERSION,
            "type": "AUTH",
            "request_id": secrets.token_urlsafe(16),
            "timestamp": int(time.time()),
            "password": self.password,
        }
        envelope = json.loads(encrypt_packet(request, self.key).decode("ascii"))
        tag = bytearray(base64.b64decode(envelope["tag"]))
        tag[-1] ^= 1
        envelope["tag"] = base64.b64encode(tag).decode("ascii")
        tampered = json.dumps(envelope, separators=(",", ":")).encode("ascii")
        response = decrypt_packet(
            server.handle_datagram(tampered, ("127.0.0.1", 41005)), self.key
        )
        self.assertFalse(response["ok"])
        self.assertEqual(0, server.active_session_count)

    def test_15_malformed_random_datagram_is_rejected_without_exception(self) -> None:
        server = self.make_server()
        response_packet = server.handle_datagram(secrets.token_bytes(100), ("127.0.0.1", 41006))
        response = decrypt_packet(response_packet, self.key)
        self.assertFalse(response["ok"])

    def test_16_truncated_packet_is_rejected(self) -> None:
        server = self.make_server()
        valid = encrypt_packet(
            {
                "version": PROTOCOL_VERSION,
                "type": "AUTH",
                "request_id": secrets.token_urlsafe(16),
                "timestamp": int(time.time()),
                "password": self.password,
            },
            self.key,
        )
        response = decrypt_packet(
            server.handle_datagram(valid[:20], ("127.0.0.1", 41007)), self.key
        )
        self.assertFalse(response["ok"])

    def test_17_unsupported_protocol_version_is_rejected(self) -> None:
        server = self.make_server()
        packet = encrypt_packet(
            {
                "version": PROTOCOL_VERSION,
                "type": "AUTH",
                "request_id": secrets.token_urlsafe(16),
                "timestamp": int(time.time()),
                "password": self.password,
            },
            self.key,
        )
        envelope = json.loads(packet.decode("ascii"))
        envelope["version"] = 2
        response = decrypt_packet(
            server.handle_datagram(
                json.dumps(envelope).encode("ascii"), ("127.0.0.1", 41008)
            ),
            self.key,
        )
        self.assertFalse(response["ok"])

    def test_18_malformed_base64_is_rejected(self) -> None:
        envelope = {
            "version": PROTOCOL_VERSION,
            "nonce": "not-base64!",
            "ciphertext": "not-base64!",
            "tag": "not-base64!",
        }
        with self.assertRaises(PacketError):
            decrypt_packet(json.dumps(envelope).encode("ascii"), self.key)

    def test_19_every_packet_uses_a_fresh_nonce(self) -> None:
        payload = {"version": PROTOCOL_VERSION, "test": True}
        first = json.loads(encrypt_packet(payload, self.key).decode("ascii"))
        second = json.loads(encrypt_packet(payload, self.key).decode("ascii"))
        self.assertNotEqual(first["nonce"], second["nonce"])

    def test_20_error_responses_are_encrypted(self) -> None:
        server = self.make_server()
        packet = server.handle_datagram(b"plaintext", ("127.0.0.1", 41009))
        self.assertNotIn(b"Invalid request", packet)
        self.assertFalse(decrypt_packet(packet, self.key)["ok"])

    # Session bounds, expiry, invalidation, and binding

    def test_21_token_has_256_bits_of_cryptographic_randomness(self) -> None:
        server = self.make_server()
        token = self.direct_authenticate(server, ("127.0.0.1", 42001))
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        decoded = base64.urlsafe_b64decode(token + "=")
        self.assertEqual(32, len(decoded))

    def test_22_server_stores_digest_not_raw_token(self) -> None:
        server = self.make_server()
        token = self.direct_authenticate(server, ("127.0.0.1", 42002))
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.assertIn(digest, server.sessions)
        self.assertNotIn(token, server.sessions)
        self.assertNotIn(token, repr(server.sessions))

    def test_23_token_expires_after_inactivity_ttl(self) -> None:
        clock = FakeClock()
        server = self.make_server(session_ttl=2, time_fn=clock)
        self.direct_authenticate(server, ("127.0.0.1", 42003))
        clock.advance(2.1)
        self.assertEqual(0, server.active_session_count)

    def test_24_expired_token_cannot_run_get_temperature(self) -> None:
        clock = FakeClock()
        server = self.make_server(session_ttl=2, time_fn=clock)
        address = ("127.0.0.1", 42004)
        token = self.direct_authenticate(server, address)
        clock.advance(2.1)
        response, _packet = self.direct_request(
            server, address, "COMMAND", token=token, command="GET_TEMP"
        )
        self.assertFalse(response["ok"])

    def test_25_successful_use_refreshes_last_used_time(self) -> None:
        clock = FakeClock()
        server = self.make_server(session_ttl=10, time_fn=clock)
        address = ("127.0.0.1", 42005)
        token = self.direct_authenticate(server, address)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        initial = server.sessions[digest].last_used_at
        clock.advance(3)
        response, _packet = self.direct_request(
            server, address, "COMMAND", token=token, command="GET_TEMP"
        )
        self.assertTrue(response["ok"])
        self.assertGreater(server.sessions[digest].last_used_at, initial)

    def test_26_logout_invalidates_session(self) -> None:
        server = self.make_server()
        address = ("127.0.0.1", 42006)
        token = self.direct_authenticate(server, address)
        response, _packet = self.direct_request(
            server, address, "LOGOUT", token=token
        )
        self.assertTrue(response["logged_out"])
        denied, _packet = self.direct_request(
            server, address, "COMMAND", token=token, command="GET_TEMP"
        )
        self.assertFalse(denied["ok"])

    def test_27_session_store_never_exceeds_maximum(self) -> None:
        server = self.make_server(max_sessions=3)
        for index in range(12):
            self.direct_authenticate(server, ("127.0.0.1", 42100 + index))
            self.assertLessEqual(server.active_session_count, 3)
        self.assertEqual(3, server.active_session_count)

    def test_28_authentication_attempts_cannot_cause_unbounded_growth(self) -> None:
        server = self.make_server(max_sessions=2)
        for index in range(20):
            response, _packet = self.direct_request(
                server,
                ("127.0.0.1", 42200 + index),
                "AUTH",
                password=self.password if index % 2 else "wrong",
            )
            self.assertLessEqual(server.active_session_count, 2)
            self.assertEqual(index % 2 == 1, response["ok"])

    def test_29_lru_session_is_evicted_at_capacity(self) -> None:
        clock = FakeClock()
        server = self.make_server(max_sessions=2, time_fn=clock)
        address_one = ("127.0.0.1", 42301)
        address_two = ("127.0.0.1", 42302)
        token_one = self.direct_authenticate(server, address_one)
        clock.advance(1)
        token_two = self.direct_authenticate(server, address_two)
        clock.advance(1)
        used, _packet = self.direct_request(
            server, address_one, "COMMAND", token=token_one, command="GET_TEMP"
        )
        self.assertTrue(used["ok"])
        clock.advance(1)
        self.direct_authenticate(server, ("127.0.0.1", 42303))
        digest_one = hashlib.sha256(token_one.encode()).hexdigest()
        digest_two = hashlib.sha256(token_two.encode()).hexdigest()
        self.assertIn(digest_one, server.sessions)
        self.assertNotIn(digest_two, server.sessions)

    def test_30_missing_token_is_rejected(self) -> None:
        server = self.make_server()
        response, _packet = self.direct_request(
            server, ("127.0.0.1", 42401), "COMMAND", command="GET_TEMP"
        )
        self.assertFalse(response["ok"])

    def test_31_wrong_address_token_use_is_rejected(self) -> None:
        server = self.make_server()
        token = self.direct_authenticate(server, ("127.0.0.1", 42402))
        response, _packet = self.direct_request(
            server,
            ("127.0.0.1", 42403),
            "COMMAND",
            token=token,
            command="GET_TEMP",
        )
        self.assertFalse(response["ok"])

    def test_32_replayed_request_is_rejected_and_cache_is_bounded(self) -> None:
        server = self.make_server(max_replay_entries=2)
        request = {
            "version": PROTOCOL_VERSION,
            "type": "AUTH",
            "request_id": secrets.token_urlsafe(16),
            "timestamp": int(time.time()),
            "password": self.password,
        }
        packet = encrypt_packet(request, self.key)
        first = decrypt_packet(
            server.handle_datagram(packet, ("127.0.0.1", 42404)), self.key
        )
        replay = decrypt_packet(
            server.handle_datagram(packet, ("127.0.0.1", 42404)), self.key
        )
        self.assertTrue(first["ok"])
        self.assertFalse(replay["ok"])
        for index in range(5):
            self.direct_request(
                server,
                ("127.0.0.1", 42410 + index),
                "AUTH",
                password="wrong",
            )
        self.assertLessEqual(len(server._seen_requests), 2)

    # Command allowlist and operational behavior

    def test_33_set_degrees_celsius_works_for_valid_session(self) -> None:
        server = self.start_server()
        client = self.make_client(server)
        token = client.authenticate(server.port, self.password)
        self.assertTrue(client.setTemperatureC(server.port, token))
        self.assertEqual("C", server.deg)

    def test_34_set_degrees_fahrenheit_works_for_valid_session(self) -> None:
        server = self.start_server()
        client = self.make_client(server)
        token = client.authenticate(server.port, self.password)
        self.assertTrue(client.setTemperatureF(server.port, token))
        self.assertEqual("F", server.deg)

    def test_35_set_degrees_kelvin_works_for_valid_session(self) -> None:
        server = self.start_server()
        client = self.make_client(server)
        token = client.authenticate(server.port, self.password)
        client.setTemperatureC(server.port, token)
        self.assertTrue(client.setTemperatureK(server.port, token))
        self.assertEqual("K", server.deg)

    def test_36_update_temperature_works_for_valid_session(self) -> None:
        source = FakeTemperatureSource()
        server = SmartNetworkThermometer(source, 0.01, 0)
        self.servers.append(server)
        address = ("127.0.0.1", 42501)
        token = self.direct_authenticate(server, address)
        calls_before = source.calls
        response, _packet = self.direct_request(
            server, address, "COMMAND", token=token, command="UPDATE_TEMP"
        )
        self.assertTrue(response["updated"])
        self.assertEqual(calls_before + 1, source.calls)

    def test_37_semicolon_command_injection_is_rejected(self) -> None:
        server = self.make_server()
        address = ("127.0.0.1", 42502)
        token = self.direct_authenticate(server, address)
        response, _packet = self.direct_request(
            server,
            address,
            "COMMAND",
            token=token,
            command="GET_TEMP;SET_DEGF",
        )
        self.assertFalse(response["ok"])
        self.assertEqual("K", server.deg)

    def test_38_unknown_command_is_rejected(self) -> None:
        server = self.make_server()
        address = ("127.0.0.1", 42503)
        token = self.direct_authenticate(server, address)
        response, _packet = self.direct_request(
            server, address, "COMMAND", token=token, command="UNKNOWN"
        )
        self.assertFalse(response["ok"])

    def test_39_unexpected_payload_type_is_rejected(self) -> None:
        server = self.make_server()
        response, _packet = self.direct_request(
            server, ("127.0.0.1", 42504), "ADMIN", command="GET_TEMP"
        )
        self.assertFalse(response["ok"])

    def test_40_server_remains_operational_after_invalid_packet(self) -> None:
        server = self.start_server()
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(raw_socket.close)
        raw_socket.settimeout(1)
        raw_socket.sendto(secrets.token_bytes(64), (server.host, server.port))
        response_packet, _address = raw_socket.recvfrom(8192)
        self.assertFalse(decrypt_packet(response_packet, self.key)["ok"])
        client = self.make_client(server)
        self.assertTrue(client.authenticate(server.port, self.password))

    def test_41_client_context_closes_socket(self) -> None:
        server = self.start_server()
        client = SimpleNetworkClient(server.port, server.port, timeout=1)
        with client:
            token = client.authenticate(server.port, self.password)
            self.assertTrue(token)
        self.assertTrue(client._closed)
        self.assertEqual(-1, client._socket.fileno())

    def test_42_importing_server_has_no_gui_thread_or_socket_side_effect(self) -> None:
        code = """
import socket
import sys
import threading

def forbidden(*args, **kwargs):
    raise RuntimeError('import attempted a runtime side effect')

socket.socket = forbidden
threading.Thread.start = forbidden
import SampleNetworkServer
assert 'matplotlib.pyplot' not in sys.modules
print('import-safe')
"""
        env = os.environ.copy()
        env.pop("INCUBATOR_AUTH_PASSWORD", None)
        env.pop("INCUBATOR_TRANSPORT_KEY", None)
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=LAB3,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("import-safe", result.stdout.strip())

    def test_43_preserved_copy_matches_manifest_after_git_line_normalization(self) -> None:
        manifest = (LAB3 / "copy" / "SHA.txt").read_text(encoding="utf-8")
        expected = dict(re.findall(r"MD5 \(([^)]+)\) = ([0-9a-f]{32})", manifest))
        self.assertTrue(expected)
        actual = {}
        for name in expected:
            data = (LAB3 / "copy" / name).read_bytes().replace(b"\r\n", b"\n")
            actual[name] = hashlib.md5(data).hexdigest()
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
