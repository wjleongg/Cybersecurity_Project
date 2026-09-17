"""Replay/substitution detection for verified payloads.

A valid signature and a matching hash only prove a payload is genuine and
unaltered — they say nothing about whether this exact presentation of it has
been seen before, or whether it was issued long enough ago that it should no
longer be trusted. `PayloadRecord.nonce` and `PayloadRecord.timestamp` exist
for that purpose (see payload.py); this module is what actually checks them.

Deliberately separate from `engine.verify()`'s call graph unless a caller
opts in by passing a `ReplayGuard` instance: `tests/test_core.py` and
`scripts/make_samples.py` both re-verify the same encoded record across many
negative-case variations (wrong key, wrong LSB depth, and so on), and those
are not replay attempts — they are the same one-time act of embedding being
inspected from different angles. Only the GUI's live verify action, which
models a real recipient seeing a file for the first time, wires up a guard
backed by a persistent store.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ReplayCheck:
    """Result of checking one (nonce, timestamp) pair."""

    ok: bool
    reason: str | None = None


class ReplayGuard:
    """Tracks nonces already verified, optionally persisted to disk.

    The store is a flat {nonce_hex: first_seen_iso} mapping. Persisting it
    is what lets the demo show "close the app, reopen, the replay is still
    caught" rather than the weaker "still open in the same session" claim.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self._seen: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        if self.path is None or not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt or half-written log should not crash verification;
            # it just means past replay history is lost, not that the file
            # being checked right now is unsafe.
            return {}

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.write_text(json.dumps(self._seen, indent=2), encoding="utf-8")

    def check(
        self,
        nonce: str,
        timestamp_iso: str,
        max_age_seconds: int | None = None,
    ) -> ReplayCheck:
        """Read-only: does this (nonce, timestamp) look like a replay?

        Nonce reuse is checked before staleness because it is the more
        specific, more certain finding — a payload can be both, but "this
        exact payload was already verified" is the more informative reason
        to report.
        """
        if nonce in self._seen:
            return ReplayCheck(
                ok=False,
                reason=(
                    f"This exact payload (nonce {nonce}) was already verified "
                    f"at {self._seen[nonce]}. A genuine sender does not "
                    "resubmit the same signed file."
                ),
            )

        if max_age_seconds is not None:
            try:
                issued = dt.datetime.fromisoformat(timestamp_iso)
            except ValueError:
                return ReplayCheck(ok=True)  # malformed timestamp: not this check's job
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=dt.timezone.utc)
            age = dt.datetime.now(dt.timezone.utc) - issued
            if age.total_seconds() > max_age_seconds:
                return ReplayCheck(
                    ok=False,
                    reason=(
                        f"Payload was issued at {timestamp_iso}, "
                        f"{age.total_seconds():.0f}s ago — older than the "
                        f"{max_age_seconds}s freshness window allowed."
                    ),
                )

        return ReplayCheck(ok=True)

    def record(self, nonce: str, timestamp_iso: str) -> None:
        """Mark a nonce as seen. Call only after `check()` has passed."""
        self._seen[nonce] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        self._save()

    def reset(self) -> None:
        """Clear all history. Backs the demo's "reset replay log" control."""
        self._seen = {}
        self._save()
