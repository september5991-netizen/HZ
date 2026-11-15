"""In-memory trust policy; transport must supply a verified peer identity."""
from dataclasses import dataclass
from datetime import datetime
from typing import FrozenSet, Mapping

from .model import Command, Decision, evaluate_command


@dataclass(frozen=True)
class AuthenticatedPeer:
    """Trusted adapter output, never constructed from untrusted message fields.

    fingerprint is the verified public-key fingerprint, not an IP or device name.
    This type itself provides no cryptographic verification.
    """
    device_id: str
    fingerprint: str


@dataclass(frozen=True)
class TrustGrant:
    device_id: str
    fingerprint: str
    actions: FrozenSet[str]
    revoked: bool = False


def evaluate_trusted_command(
    command: Command, *, peer: AuthenticatedPeer,
    grants: Mapping[str, TrustGrant], local_device_id: str,
    processed_ids: FrozenSet[str], now: datetime,
) -> Decision:
    """Check current trust on every command; ACCEPT still requires durable dedup."""
    if not isinstance(peer, AuthenticatedPeer):
        return Decision.DENY
    if not isinstance(peer.device_id, str) or not isinstance(peer.fingerprint, str):
        return Decision.DENY
    if not peer.device_id.strip() or not peer.fingerprint.strip():
        return Decision.DENY
    if command.sender_id != peer.device_id:
        return Decision.DENY
    grant = grants.get(peer.device_id)
    if (not isinstance(grant, TrustGrant) or grant.revoked
            or grant.device_id != peer.device_id
            or grant.fingerprint != peer.fingerprint):
        return Decision.DENY
    return evaluate_command(
        command, local_device_id=local_device_id,
        trusted_senders=frozenset({peer.device_id}),
        allowed_actions={peer.device_id: grant.actions},
        processed_ids=processed_ids, now=now,
    )
