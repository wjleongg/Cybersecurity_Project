"""Ledger panel and ledger-aware presentation.

Kept out of media_tab because the ledger is genuinely optional: everything
here degrades to a single caption when no database is configured, and none of
it is allowed to block the cryptographic workflow.

The composition rule implemented here is the important part. The six verdicts
are fixed by the brief and are what cryptography alone establishes, so they
are never rewritten. The ledger is shown as a second, independent line, and
only when it actively contradicts an Authentic verdict — a revoked or reused
identity — does the panel raise a banner saying so.
"""

import streamlit as st

from core.ledger import LedgerConfig, LedgerStatus, build_ledger
from core.engine import Verdict

_STATUS_STYLE = {
    LedgerStatus.REGISTERED: ("#0F6E56", "#E1F5EE"),
    LedgerStatus.UNKNOWN: ("#854F0B", "#FAEEDA"),
    LedgerStatus.SUBSTITUTED: ("#A32D2D", "#FCEBEB"),
    LedgerStatus.REVOKED: ("#A32D2D", "#FCEBEB"),
    LedgerStatus.UNAVAILABLE: ("#5A5A55", "#EFEEE9"),
    LedgerStatus.DISABLED: ("#5A5A55", "#EFEEE9"),
}


@st.cache_resource(show_spinner=False)
def _cached_ledger(url: str, key: str):
    """One ledger client per configuration, reused across reruns.

    cache_resource rather than cache_data: this holds a requests.Session with
    a connection pool, which should outlive a rerun rather than being rebuilt
    on every keystroke.
    """
    return build_ledger(LedgerConfig(url=url, key=key))


def get_ledger():
    """Build the ledger from Streamlit secrets, or a null one if absent.

    Reading secrets is wrapped because st.secrets raises when no secrets file
    exists at all, which is the normal state for a teammate who has just
    cloned the repository.
    """
    try:
        section = st.secrets.get("supabase", {})
        url = section.get("url", "")
        key = section.get("key", "")
    except Exception:
        url, key = "", ""
    return _cached_ledger(url, key)


def status_line(result) -> None:
    """One coloured line reporting what the ledger knows."""
    colour, background = _STATUS_STYLE[result.status]
    st.markdown(
        f"""
        <div style="border:1px solid {colour};background:{background};
                    border-radius:10px;padding:0.6rem 0.9rem;margin:0 0 0.75rem;">
          <span style="font-weight:600;color:{colour};">Ledger · {result.status.value}</span>
          <span style="color:{colour};font-size:0.88rem;"> — {result.message}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def contradiction_banner(verdict: Verdict, result) -> None:
    """Raised only when the ledger disagrees with a clean crypto verdict.

    A file can be perfectly signed, perfectly intact, and still not something
    the issuer stands behind any more. That gap is the entire argument for
    keeping state, so it gets its own banner rather than a quiet line.
    """
    if verdict != Verdict.AUTHENTIC or not result.is_blocking:
        return
    st.error(
        "The cryptography checks out but the ledger says do not trust this file. "
        "A signature proves who issued a record and that it has not changed; it "
        "cannot withdraw a record after the fact. Only the ledger can.",
        icon=":material/gpp_bad:",
    )


def render_panel() -> None:
    """The ledger tab: connection state, revocation, and recent activity."""
    from ui import auth  # Add this import at the top of the file
    
    ledger = get_ledger()

    if not ledger.enabled:
        st.info(
            "No ledger is configured, so the tool is running on cryptography "
            "alone. Add Supabase credentials to `.streamlit/secrets.toml` to "
            "enable issuance registration, revocation and the audit trail.",
            icon=":material/database_off:",
        )
        with st.expander("How to configure it"):
            st.code(
                '[supabase]\n'
                'url = "https://YOUR-PROJECT.supabase.co"\n'
                'key = "YOUR-ANON-KEY"\n',
                language="toml",
            )
            st.caption(
                "Run `supabase_schema.sql` in the Supabase SQL editor first. "
                "Use the anon key, never the service role key."
            )
        return

    issuances = ledger.recent_issuances(limit=25)
    verifications = ledger.recent_verifications(limit=25)

    st.success(
        f"Ledger connected · {len(issuances)} recent issuance(s), "
        f"{len(verifications)} recent verification(s).",
        icon=":material/database:",
    )

    st.divider()
    st.markdown("**Revoke a record**")
    st.caption(
        "Withdraws a media ID the issuer no longer stands behind. The file "
        "stays cryptographically valid; the ledger is what changes."
    )
    
    # Require authentication before showing revoke controls
    if not auth.require_admin_password():
        st.warning(
            "You must authenticate to access revocation. This protects the "
            "ledger from unauthorized changes.",
            icon=":material/lock:",
        )
        return
    
    # Only authenticated users see and can use the revoke button
    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        media_id = st.text_input(
            "Media ID", key="revoke_media_id", placeholder="IMG-…"
        )
    with c2:
        reason = st.text_input(
            "Reason", key="revoke_reason", placeholder="superseded by a newer release"
        )
    with c3:
        st.write("")
        st.write("")
        if st.button("Revoke", width="stretch"):
            if not media_id:
                st.warning("Enter a media ID to revoke.")
            else:
                result = ledger.revoke(media_id.strip(), reason.strip())
                if result.status == LedgerStatus.REVOKED:
                    st.success(result.message)
                else:
                    st.warning(result.message)
                st.rerun()

    if st.session_state.get("admin_authenticated"):
        if st.button("Logout", use_container_width=True):
            auth.logout()
            st.rerun()

    st.divider()

    left, right = st.columns(2)
    with left:
        st.markdown("**Issued records**")
        if issuances:
            st.dataframe(
                [
                    {
                        "Media ID": r.get("media_id"),
                        "Type": r.get("media_type"),
                        "Issuer": r.get("issuer"),
                        "Issued": (r.get("issued_at") or "")[:19],
                        "Revoked": "yes" if r.get("revoked") else "",
                    }
                    for r in issuances
                ],
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption("Nothing issued yet. Embed a payload to create the first entry.")

    with right:
        st.markdown("**Verification log**")
        if verifications:
            st.dataframe(
                [
                    {
                        "Media ID": r.get("media_id") or "—",
                        "Verdict": r.get("verdict"),
                        "Ledger": r.get("ledger_status"),
                        "Checked": (r.get("checked_at") or "")[:19],
                    }
                    for r in verifications
                ],
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption("No verifications recorded yet.")

    st.caption(
        "Both tables are append-only. Revocation marks a row rather than "
        "deleting it, so the withdrawal itself stays auditable."
    )
