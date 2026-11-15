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


if __name__ == "__main__":
    unittest.main()
