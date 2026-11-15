"""Strict JSON command codec. Decoding does not authenticate or authorize."""
import json
import re
from dataclasses import replace
from datetime import datetime, timezone

from .model import Command, Decision, evaluate_command

MAX_MESSAGE_BYTES = 32768
FIELDS = {"version", "command_id", "sender_id", "recipient_id", "action", "payload", "expires_at"}
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", re.ASCII)


class ProtocolError(ValueError):
    """Malformed or unsupported wire command."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ProtocolError("non-finite JSON number")


def _validate(command):
    if not isinstance(command, Command) or not isinstance(command.expires_at, datetime):
        raise ProtocolError("invalid command")
    # Reuse structural validation without treating expiry as a syntax error.
    verdict = evaluate_command(
        replace(command, expires_at=datetime(2001, 1, 1, tzinfo=timezone.utc)), local_device_id=command.recipient_id,
        trusted_senders=frozenset({command.sender_id}) if isinstance(command.sender_id, str) else frozenset(),
        allowed_actions={command.sender_id: frozenset({"ping", "message"})} if isinstance(command.sender_id, str) else {},
        processed_ids=frozenset(), now=datetime.min.replace(tzinfo=timezone.utc),
    )
    if verdict not in {Decision.ACCEPT, Decision.EXPIRED}:
        raise ProtocolError("invalid command fields")
    if command.expires_at.utcoffset() is None:
        raise ProtocolError("timezone required")
    for value in (command.sender_id, command.recipient_id):
        if len(value) > 256:
            raise ProtocolError("device identifier too long")


def encode_command(command: Command) -> bytes:
    """Encode deterministic UTF-8 JSON; not a signature canonicalization scheme."""
    try:
        _validate(command)
        timestamp = command.expires_at.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        data = dict(version=command.version, command_id=command.command_id,
                    sender_id=command.sender_id, recipient_id=command.recipient_id,
                    action=command.action, payload=command.payload, expires_at=timestamp)
        wire = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(wire) > MAX_MESSAGE_BYTES:
            raise ProtocolError("command too large")
        return wire
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ProtocolError("cannot encode command") from exc


def decode_command(wire: bytes) -> Command:
    """Parse exactly one bounded command; unknown fields and duplicate keys fail."""
    if not isinstance(wire, bytes) or len(wire) > MAX_MESSAGE_BYTES:
        raise ProtocolError("expected bounded bytes")
    try:
        data = json.loads(wire.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(data, dict) or set(data) != FIELDS:
            raise ProtocolError("unexpected envelope fields")
        stamp = data["expires_at"]
        if not isinstance(stamp, str) or TIMESTAMP.fullmatch(stamp) is None:
            raise ProtocolError("expected UTC timestamp with six fractional digits")
        data["expires_at"] = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        command = Command(**data)
        _validate(command)
        # Reject unpaired surrogates and enforce encoder limits too.
        encode_command(command)
        return command
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ProtocolError("invalid command JSON") from exc
