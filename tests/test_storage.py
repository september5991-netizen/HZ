import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from onecore_protocol import Command
from onecore_protocol.storage import CommandJournal, CommandConflict, Outcome


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "journal.sqlite"
        self.command = Command(1, "12345678-1234-4234-8234-123456789abc",
                               "windows", "android", "ping", {},
                               datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.journal = CommandJournal(self.path)

    def tearDown(self):
        self.journal.close()
        self.tmp.cleanup()

    def test_reservation_survives_restart(self):
        self.assertTrue(self.journal.reserve(self.command))
        self.journal.close()
        self.journal = CommandJournal(self.path)
        self.assertFalse(self.journal.reserve(self.command))
        self.assertEqual(self.journal.outcome(self.command.command_id), Outcome.ACCEPTED)

    def test_conflicting_content(self):
        self.journal.reserve(self.command)
        for command in [replace(self.command, sender_id="other"),
                        replace(self.command, action="message", payload={"text": "changed"})]:
            with self.assertRaises(CommandConflict):
                self.journal.reserve(command)

    def test_independent_connections_reserve_once(self):
        other = CommandJournal(self.path)
        try:
            self.assertTrue(self.journal.reserve(self.command))
            self.assertFalse(other.reserve(self.command))
        finally:
            other.close()

    def test_terminal_results_survive_restart(self):
        for index, result in enumerate([Outcome.EXECUTED, Outcome.FAILED, Outcome.UNKNOWN]):
            command = replace(self.command, command_id=f"12345678-1234-4234-8234-{index:012d}")
            self.assertTrue(self.journal.reserve(command))
            self.journal.finish(command.command_id, result)
            self.journal.close()
            self.journal = CommandJournal(self.path)
            self.assertEqual(self.journal.outcome(command.command_id), result)
            self.assertFalse(self.journal.reserve(command))
            with self.assertRaises(ValueError):
                self.journal.finish(command.command_id, Outcome.FAILED)

    def test_invalid_transition(self):
        with self.assertRaises(ValueError):
            self.journal.finish(self.command.command_id, Outcome.EXECUTED)
        self.journal.reserve(self.command)
        with self.assertRaises(ValueError):
            self.journal.finish(self.command.command_id, Outcome.ACCEPTED)
