"""The issuance ledger.

Signatures and hashes answer two questions completely: was this issued by the
holder of a key, and has the media changed since. They cannot answer a third,
because a signature is a static offline artefact and cannot be un-said:

    is this record still one the issuer stands behind?

That is what the ledger is for. It records every payload at the moment it is
embedded, and lets a verifier ask three further questions:

    registered    was this media ID actually issued by our process, or merely
                  signed by some key that happens to verify?
    substituted   has this media ID been seen before carrying a different
                  cover hash — that is, did someone reuse an identity?
    revoked       has the issuer withdrawn this record since signing it?

Revocation is the one that cryptography genuinely cannot do alone, and it is
the strongest argument for keeping state at all.

Design constraints this module holds to:

  No Streamlit import. The ledger is domain logic and is tested headlessly.

  No exception ever escapes. Every method returns a result object, and a
  network failure degrades to UNAVAILABLE rather than raising. A demo must
  not die because campus wifi dropped, and a verifier that cannot reach the
  ledger should still be able to report what cryptography alone established.

  The ledger never overrides the cryptographic verdict. It is reported
  alongside as an independent second opinion. Composition of the two is a
  presentation decision, made in the UI, not buried in here.

Transport is PostgREST, Supabase's auto-generated REST API, over plain HTTPS.
The supabase-py client would also work; direct REST is used because it adds no
dependency and its request shape is stable across versions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import requests

DEFAULT_TIMEOUT = 6.0          # seconds; a demo cannot wait longer than this
ISSUED_TABLE = "issued_records"
VERIFICATION_TABLE = "verification_log"


class LedgerStatus(str, Enum):
    """What the ledger knows about a record."""

    REGISTERED = "Registered"        # issued by us, matches what we recorded
    UNKNOWN = "Not in ledger"        # signature fine, but we never issued this
    SUBSTITUTED = "Identity reused"  # same media ID, different cover hash
    REVOKED = "Revoked"              # issuer has withdrawn this record
    UNAVAILABLE = "Ledger offline"   # could not reach the database
    DISABLED = "Ledger disabled"     # not configured at all


# Whether a status should stop someone trusting an otherwise valid file.
BLOCKING_STATUSES = {LedgerStatus.REVOKED, LedgerStatus.SUBSTITUTED}


@dataclass
class LedgerResult:
    """Outcome of a ledger operation."""

    status: LedgerStatus
    message: str
    record: dict[str, Any] | None = None

    @property
    def is_blocking(self) -> bool:
        return self.status in BLOCKING_STATUSES


@dataclass
class LedgerConfig:
    """Connection settings, normally read from Streamlit secrets."""

    url: str = ""
    key: str = ""
    timeout: float = DEFAULT_TIMEOUT

    @property
    def configured(self) -> bool:
        return bool(self.url and self.key)

    @property
    def rest_url(self) -> str:
        return f"{self.url.rstrip('/')}/rest/v1"


class NullLedger:
    """Used when no database is configured.

    Every method succeeds and reports DISABLED. This is what keeps the ledger
    an optional layer: a teammate who has not set up secrets still gets a
    fully working tool, minus one panel.
    """

    enabled = False

    def register(self, *args, **kwargs) -> LedgerResult:
        return LedgerResult(LedgerStatus.DISABLED, "No ledger is configured.")

    def check(self, *args, **kwargs) -> LedgerResult:
        return LedgerResult(LedgerStatus.DISABLED, "No ledger is configured.")

    def revoke(self, *args, **kwargs) -> LedgerResult:
        return LedgerResult(LedgerStatus.DISABLED, "No ledger is configured.")

    def log_verification(self, *args, **kwargs) -> None:
        return None

    def recent_issuances(self, limit: int = 20) -> list[dict]:
        return []

    def recent_verifications(self, limit: int = 20) -> list[dict]:
        return []


class SupabaseLedger:
    """Issuance ledger backed by a Supabase Postgres table."""

    enabled = True

    def __init__(self, config: LedgerConfig):
        self.config = config
        self._session = requests.Session()
        self._session.headers.update(
            {
                "apikey": config.key,
                "Authorization": f"Bearer {config.key}",
                "Content-Type": "application/json",
            }
        )

    # -- transport ---------------------------------------------------------

    def _request(self, method: str, table: str, **kwargs):
        """One HTTP call. Returns (ok, parsed_json_or_error_string)."""
        url = f"{self.config.rest_url}/{table}"
        try:
            response = self._session.request(
                method, url, timeout=self.config.timeout, **kwargs
            )
        except requests.RequestException as exc:
            return False, f"could not reach the ledger: {exc}"

        if response.status_code >= 400:
            # PostgREST puts a useful message in the body; surface it rather
            # than a bare status code, because the usual cause is a missing
            # row-level-security policy and that is worth naming explicitly.
            return False, f"ledger returned {response.status_code}: {response.text[:300]}"

        if not response.content:
            return True, []
        try:
            return True, response.json()
        except ValueError:
            return True, []

    # -- writes ------------------------------------------------------------

    def register(self, record, signer_fingerprint: str) -> LedgerResult:
        """Record a payload at the moment it is embedded.

        Called after a successful embed. A failure here is reported but must
        not invalidate the embed that already succeeded — the stego file is
        real whether or not the ledger heard about it.
        """
        row = {
            "media_id": record.media_id,
            "nonce": record.nonce,
            "cover_hash": record.cover_hash,
            "media_type": record.media_type,
            "issuer": record.issuer,
            "signer_fingerprint": signer_fingerprint,
            "n_lsb": record.n_lsb,
            "payload_kind": record.payload_kind,
            "filename": record.filename or None,
            "issued_at": record.timestamp,
        }
        ok, body = self._request(
            "POST", ISSUED_TABLE, json=row, headers={"Prefer": "return=representation"}
        )
        if not ok:
            return LedgerResult(LedgerStatus.UNAVAILABLE, str(body))
        stored = body[0] if isinstance(body, list) and body else None
        return LedgerResult(
            LedgerStatus.REGISTERED,
            f"Registered {record.media_id} in the ledger.",
            stored,
        )

    def revoke(self, media_id: str, reason: str) -> LedgerResult:
        """Withdraw a record the issuer no longer stands behind."""
        ok, body = self._request(
            "PATCH",
            ISSUED_TABLE,
            params={"media_id": f"eq.{media_id}"},
            json={"revoked": True, "revoked_reason": reason or "no reason given"},
            headers={"Prefer": "return=representation"},
        )
        if not ok:
            return LedgerResult(LedgerStatus.UNAVAILABLE, str(body))
        if not body:
            return LedgerResult(
                LedgerStatus.UNKNOWN,
                f"No ledger entry for {media_id}, so nothing was revoked.",
            )
        return LedgerResult(
            LedgerStatus.REVOKED, f"Revoked {media_id}.", body[0]
        )

    def log_verification(
        self,
        media_id: str | None,
        media_type: str,
        verdict: str,
        ledger_status: str,
        signer_fingerprint: str,
        detail: str = "",
    ) -> None:
        """Append to the audit trail. Best effort; failures are swallowed.

        This is the only method that ignores its own errors. An audit write
        that fails must never change what the verifier sees, and a verifier
        who cannot reach the ledger has already been told so by check().
        """
        self._request(
            "POST",
            VERIFICATION_TABLE,
            json={
                "media_id": media_id,
                "media_type": media_type,
                "verdict": verdict,
                "ledger_status": ledger_status,
                "signer_fingerprint": signer_fingerprint,
                "detail": detail[:500],
            },
        )

    # -- reads -------------------------------------------------------------

    def check(self, record) -> LedgerResult:
        """Ask the ledger what it knows about an extracted record.

        The comparison that matters is cover_hash. A media ID appearing again
        with a different cover hash means the identity was reused for
        different content, which is exactly the substitution case the nonce
        and media ID exist to make detectable.
        """
        ok, body = self._request(
            "GET",
            ISSUED_TABLE,
            params={"media_id": f"eq.{record.media_id}", "select": "*"},
        )
        if not ok:
            return LedgerResult(LedgerStatus.UNAVAILABLE, str(body))

        if not body:
            return LedgerResult(
                LedgerStatus.UNKNOWN,
                (
                    "This media ID is not in the ledger. The signature may still "
                    "be valid — the file could have been issued by another "
                    "instance, or before this ledger existed."
                ),
            )

        row = body[0]

        if row.get("cover_hash") != record.cover_hash:
            return LedgerResult(
                LedgerStatus.SUBSTITUTED,
                (
                    "This media ID was issued against a different cover hash. "
                    "The identity has been reused for different content."
                ),
                row,
            )

        if row.get("revoked"):
            reason = row.get("revoked_reason") or "no reason recorded"
            return LedgerResult(
                LedgerStatus.REVOKED,
                (
                    f"The issuer has revoked this record ({reason}). The "
                    "signature is still mathematically valid; the issuer no "
                    "longer stands behind what it says."
                ),
                row,
            )

        if row.get("nonce") != record.nonce:
            return LedgerResult(
                LedgerStatus.SUBSTITUTED,
                (
                    "The cover hash matches but the nonce does not. Two "
                    "different payloads have been issued for the same media ID."
                ),
                row,
            )

        return LedgerResult(
            LedgerStatus.REGISTERED,
            (
                f"Issued {row.get('issued_at', 'at an unrecorded time')} by "
                f"{row.get('issuer') or 'an unnamed issuer'}, and not revoked."
            ),
            row,
        )

    def recent_issuances(self, limit: int = 20) -> list[dict]:
        ok, body = self._request(
            "GET",
            ISSUED_TABLE,
            params={"select": "*", "order": "issued_at.desc", "limit": str(limit)},
        )
        return body if ok and isinstance(body, list) else []

    def recent_verifications(self, limit: int = 20) -> list[dict]:
        ok, body = self._request(
            "GET",
            VERIFICATION_TABLE,
            params={"select": "*", "order": "checked_at.desc", "limit": str(limit)},
        )
        return body if ok and isinstance(body, list) else []


def build_ledger(config: LedgerConfig | None):
    """Return a working ledger, or a null one when unconfigured."""
    if config is None or not config.configured:
        return NullLedger()
    return SupabaseLedger(config)
