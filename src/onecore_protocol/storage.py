"""Durable command reservation. Not an executor or authentication layer."""
import hashlib
import sqlite3
from enum import Enum

from .codec import encode_command
from .model import Command


class Outcome(str, Enum):
    ACCEPTED = "accepted"
    EXECUTED = "executed"
    FAILED = "failed"
    UNKNOWN = "unknown_outcome"


class CommandConflict(ValueError):
    pass


class CommandJournal:
    """One local-device database; call reserve only after current authorization.

    Pending records after restart are unresolved, never permission to retry.
    SQLite commits reservation before reserve returns. No external side effect
    can be made atomic with this database; exactly-once is not guaranteed.
    """
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS commands (
            command_id TEXT PRIMARY KEY, sender_id TEXT NOT NULL,
            digest TEXT NOT NULL, outcome TEXT NOT NULL)""")
        self.db.commit()

    def close(self):
        self.db.close()

    def reserve(self, command: Command) -> bool:
        """True only for the first durable reservation; False for same content."""
        digest = hashlib.sha256(encode_command(command)).hexdigest()
        with self.db:
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO commands VALUES (?, ?, ?, ?)",
                (command.command_id, command.sender_id, digest, Outcome.ACCEPTED.value))
            if cursor.rowcount == 1:
                return True
            row = self.db.execute(
                "SELECT sender_id, digest FROM commands WHERE command_id=?",
                (command.command_id,)).fetchone()
            if row != (command.sender_id, digest):
                raise CommandConflict("command ID reused with different content")
            return False

    def outcome(self, command_id):
        row = self.db.execute("SELECT outcome FROM commands WHERE command_id=?", (command_id,)).fetchone()
        return None if row is None else Outcome(row[0])

    def finish(self, command_id, outcome: Outcome):
        """Only accepted -> terminal. Terminal states cannot be overwritten."""
        if not isinstance(outcome, Outcome) or outcome == Outcome.ACCEPTED:
            raise ValueError("terminal outcome required")
        with self.db:
            cursor = self.db.execute(
                "UPDATE commands SET outcome=? WHERE command_id=? AND outcome=?",
                (outcome.value, command_id, Outcome.ACCEPTED.value))
            if cursor.rowcount != 1:
                raise ValueError("missing or already completed reservation")
