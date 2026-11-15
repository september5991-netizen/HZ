import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from onecore_protocol import Command, Decision
from onecore_protocol.codec import encode_command, decode_command, ProtocolError, MAX_MESSAGE_BYTES
from onecore_protocol.trust import AuthenticatedPeer, TrustGrant, evaluate_trusted_command


class CodecTrustTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.command = Command(1, "12345678-1234-4234-8234-123456789abc",
                               "windows", "android", "message", {"text": "Привет 🌍"},
                               self.now + timedelta(minutes=1))
        self.peer = AuthenticatedPeer("windows", "test-key-fingerprint")
        self.grant = TrustGrant("windows", self.peer.fingerprint, frozenset({"ping", "message"}))
        self.context = dict(peer=self.peer, grants={"windows": self.grant},
                            local_device_id="android", processed_ids=frozenset(), now=self.now)

    def test_round_trip(self):
        for command in [self.command, replace(self.command, action="ping", payload={})]:
            wire = encode_command(command)
            self.assertEqual(decode_command(wire), command)
            self.assertEqual(encode_command(decode_command(wire)), wire)

    def test_timezone_normalization(self):
        command = replace(self.command, expires_at=self.command.expires_at.astimezone(timezone(timedelta(hours=10))))
        self.assertEqual(encode_command(command), encode_command(self.command))

    def test_expired_is_syntactically_valid(self):
        command = replace(self.command, expires_at=self.now - timedelta(days=1))
        self.assertEqual(decode_command(encode_command(command)), command)

    def test_reject_malformed_wire(self):
        valid = encode_command(self.command)
        for wire in [b"{}", b"[]", b"null", b"NaN", b"Infinity", b"\xff",
                     valid + b"{}", b"x" * (MAX_MESSAGE_BYTES + 1),
                     b'{"version":1,"version":1}',
                     b"[" * 2000 + b"]" * 2000]:
            with self.subTest(wire=wire[:40]):
                with self.assertRaises(ProtocolError):
                    decode_command(wire)

    def test_reject_invalid_fields(self):
        base = json.loads(encode_command(self.command))
        for key, value in [("version", True), ("version", 2), ("sender_id", []),
                           ("recipient_id", ""), ("action", "shell"),
                           ("payload", {"text": "ok", "extra": "x"}),
                           ("expires_at", "2026-01-01T00:00:00"),
                           ("expires_at", "2026-02-30T00:00:00.000000Z"),
                           ("command_id", self.command.command_id.upper())]:
            with self.subTest(key=key, value=value):
                with self.assertRaises(ProtocolError):
                    decode_command(json.dumps(dict(base, **{key: value})).encode())
        for data in [dict(base, extra=1), {k: v for k, v in base.items() if k != "action"}]:
            with self.assertRaises(ProtocolError):
                decode_command(json.dumps(data).encode())

    def test_duplicate_nested_keys(self):
        wire = encode_command(self.command).replace(
            '"text":"Привет 🌍"'.encode(), b'"text":"one","text":"two"')
        with self.assertRaises(ProtocolError):
            decode_command(wire)

    def test_encoder_rejects_invalid(self):
        for command in [replace(self.command, sender_id=[]),
                        replace(self.command, expires_at=None),
                        replace(self.command, payload={"text": "\ud800"}),
                        replace(self.command, sender_id="x" * 257)]:
            with self.assertRaises(ProtocolError):
                encode_command(command)

    def test_trusted_round_trip(self):
        self.assertEqual(evaluate_trusted_command(decode_command(encode_command(self.command)), **self.context), Decision.ACCEPT)

    def test_spoofed_or_unverified_peer(self):
        for peer in [None, AuthenticatedPeer("intruder", self.peer.fingerprint),
                     AuthenticatedPeer("windows", "different-key"), AuthenticatedPeer("windows", "")]:
            self.assertEqual(evaluate_trusted_command(self.command, **dict(self.context, peer=peer)), Decision.DENY)

    def test_revocation_and_permissions(self):
        for grants in [{}, {"windows": replace(self.grant, revoked=True)},
                       {"windows": replace(self.grant, actions=frozenset({"ping"}))},
                       {"windows": replace(self.grant, device_id="other")}]:
            self.assertEqual(evaluate_trusted_command(self.command, **dict(self.context, grants=grants)), Decision.DENY)

    def test_target_expiry_and_replay(self):
        self.assertEqual(evaluate_trusted_command(replace(self.command, recipient_id="other"), **self.context), Decision.DENY)
        self.assertEqual(evaluate_trusted_command(replace(self.command, expires_at=self.now), **self.context), Decision.EXPIRED)
        self.assertEqual(evaluate_trusted_command(self.command, **dict(self.context, processed_ids=frozenset({self.command.command_id}))), Decision.DUPLICATE)
