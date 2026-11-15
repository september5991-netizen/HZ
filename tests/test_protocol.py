import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from onecore_protocol import Command, Decision, evaluate_command


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.command = Command(1, str(uuid4()), "windows", "android", "ping", {}, self.now + timedelta(minutes=1))
        self.context = dict(local_device_id="android", trusted_senders=frozenset({"windows"}), allowed_actions={"windows": frozenset({"ping", "message"})}, processed_ids=frozenset(), now=self.now)

    def test_accept(self):
        self.assertEqual(evaluate_command(self.command, **self.context), Decision.ACCEPT)

    def test_wrong_target(self):
        self.assertEqual(evaluate_command(replace(self.command, recipient_id="other"), **self.context), Decision.DENY)

    def test_unknown_sender(self):
        self.assertEqual(evaluate_command(replace(self.command, sender_id="intruder"), **self.context), Decision.DENY)

    def test_expired(self):
        self.assertEqual(evaluate_command(replace(self.command, expires_at=self.now), **self.context), Decision.EXPIRED)

    def test_duplicate(self):
        ctx = dict(self.context, processed_ids=frozenset({self.command.command_id}))
        self.assertEqual(evaluate_command(self.command, **ctx), Decision.DUPLICATE)

    def test_disallowed_action(self):
        self.assertEqual(evaluate_command(replace(self.command, action="delete_files"), **self.context), Decision.DENY)

    def test_invalid_id(self):
        self.assertEqual(evaluate_command(replace(self.command, command_id="abc"), **self.context), Decision.DENY)

    def test_message_length(self):
        msg = replace(self.command, action="message", payload={"text": "x" * 4097})
        self.assertEqual(evaluate_command(msg, **self.context), Decision.DENY)



    def test_invalid_field_types(self):
        for field, value in [
            ("version", True), ("version", 1.0), ("sender_id", []),
            ("recipient_id", 42), ("action", []), ("expires_at", "tomorrow"),
            ("expires_at", None), ("payload", []),
        ]:
            with self.subTest(field=field, value=value):
                self.assertEqual(evaluate_command(replace(self.command, **{field: value}), **self.context), Decision.DENY)

    def test_noncanonical_uuid(self):
        for value in [self.command.command_id.upper(), self.command.command_id.replace("-", ""),
                      "{" + self.command.command_id + "}"]:
            with self.subTest(value=value):
                self.assertEqual(evaluate_command(replace(self.command, command_id=value), **self.context), Decision.DENY)

    def test_naive_time(self):
        self.assertEqual(evaluate_command(replace(self.command, expires_at=self.now.replace(tzinfo=None)), **self.context), Decision.DENY)
        self.assertEqual(evaluate_command(self.command, **dict(self.context, now=self.now.replace(tzinfo=None))), Decision.DENY)

    def test_action_permission_and_revocation(self):
        for changes in [dict(allowed_actions={}), dict(trusted_senders=frozenset())]:
            self.assertEqual(evaluate_command(self.command, **dict(self.context, **changes)), Decision.DENY)

    def test_message_contract(self):
        for payload in [{"text": "hello"}, {"text": ""}, {"text": "x" * 4096}]:
            self.assertEqual(evaluate_command(replace(self.command, action="message", payload=payload), **self.context), Decision.ACCEPT)
        for payload in [{}, {"text": 42}, {"text": "hello", "extra": "data"}]:
            self.assertEqual(evaluate_command(replace(self.command, action="message", payload=payload), **self.context), Decision.DENY)

    def test_ping_rejects_payload(self):
        self.assertEqual(evaluate_command(replace(self.command, payload={"text": "hello"}), **self.context), Decision.DENY)

    def test_equivalent_timezone_expiry(self):
        shifted = self.now.astimezone(timezone(timedelta(hours=10)))
        self.assertEqual(evaluate_command(replace(self.command, expires_at=shifted), **self.context), Decision.EXPIRED)

if __name__ == "__main__":
    unittest.main()
