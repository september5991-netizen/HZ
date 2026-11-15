"""Pure protocol validation. Trust and cryptographic identity are future work."""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import FrozenSet, Mapping
from uuid import UUID


class Decision(str, Enum):
    ACCEPT = "accept"
    DENY = "deny"
    EXPIRED = "expired"
    DUPLICATE = "duplicate"


@dataclass(frozen=True)
class Command:
    version: int
    command_id: str
    sender_id: str
    recipient_id: str
    action: str
    payload: Mapping[str, str]
    expires_at: datetime


def evaluate_command(
    command: Command,
    *,
    local_device_id: str,
    trusted_senders: FrozenSet[str],
    allowed_actions: Mapping[str, FrozenSet[str]],
    processed_ids: FrozenSet[str],
    now: datetime,
) -> Decision:
    """Validate envelope and local allowlist; caller must authenticate sender first.

    ACCEPT does NOT authorize execution without authenticated transport and
    durable deduplication. This is a non-executable reference validator.
    """
    if command.version != 1 or not command.sender_id or not command.recipient_id:
        return Decision.DENY
    try:
        UUID(command.command_id)
    except (ValueError, TypeError, AttributeError):
        return Decision.DENY
    if command.recipient_id != local_device_id:
        return Decision.DENY
    if command.sender_id not in trusted_senders:
        return Decision.DENY
    if command.action not in {"ping", "message"}:
        return Decision.DENY
    if command.action not in allowed_actions.get(command.sender_id, frozenset()):
        return Decision.DENY
    if command.expires_at.tzinfo is None or now.tzinfo is None:
        return Decision.DENY
    if command.expires_at.astimezone(timezone.utc) <= now.astimezone(timezone.utc):
        return Decision.EXPIRED
    if command.command_id in processed_ids:
        return Decision.DUPLICATE
    if not isinstance(command.payload, dict):
        return Decision.DENY
    if command.action == "message" and (not isinstance(command.payload.get("text"), str) or len(command.payload["text"]) > 4096):
        return Decision.DENY
    if command.action == "ping" and command.payload:
        return Decision.DENY
    return Decision.ACCEPT
