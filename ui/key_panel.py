"""The signing key panel.

Sits above the media tabs because one keypair signs both image and audio
payloads. Putting a copy inside each tab would allow the two to hold different
keys, which would make a verification failure ambiguous: you would not know
whether the file was bad or the tab was.

The fingerprint is displayed prominently. When demonstrating the wrong-key
negative case, being able to point at two different fingerprints turns "it
says invalid" into "it says invalid because this is a different key".
"""

import streamlit as st

from core import crypto_utils
from ui import state


def render() -> None:
    """Draw the key panel and update session state in place."""
    with st.container(border=True):
        st.markdown("**Signing keys** — shared by both tabs")

        col_gen, col_priv, col_pub = st.columns(3)

        with col_gen:
            if st.button("Generate keypair", width="stretch"):
                kp = crypto_utils.generate_keypair()
                st.session_state["keypair"] = kp
                st.session_state["public_key"] = kp.public_key
                st.session_state["public_key_source"] = "generated in this session"
                st.rerun()

        with col_priv:
            priv_file = st.file_uploader(
                "Private key (PEM)", type=["pem"], key="priv_upload",
                label_visibility="collapsed",
            )
            st.caption("Private key (PEM)")
            if priv_file is not None:
                try:
                    priv = crypto_utils.load_private_key(priv_file.getvalue())
                    st.session_state["keypair"] = crypto_utils.KeyPair(
                        private_key=priv, public_key=priv.public_key()
                    )
                    if st.session_state.get("public_key") is None:
                        st.session_state["public_key"] = priv.public_key()
                        st.session_state["public_key_source"] = "derived from private key"
                except Exception as exc:
                    st.error(f"Could not read that private key: {exc}")

        with col_pub:
            pub_file = st.file_uploader(
                "Public key (PEM)", type=["pem"], key="pub_upload",
                label_visibility="collapsed",
            )
            st.caption("Public key (PEM) — used for verifying")
            if pub_file is not None:
                try:
                    st.session_state["public_key"] = crypto_utils.load_public_key(
                        pub_file.getvalue()
                    )
                    st.session_state["public_key_source"] = pub_file.name
                except Exception as exc:
                    st.error(f"Could not read that public key: {exc}")

        _render_status()
        _render_downloads()

        st.divider()
        st.text_input(
            "Stego key",
            key="stego_key",
            type="password",
            help=(
                "Shared secret. Determines where the payload starts and what the "
                "container's marker looks like. Both parties need the same value; "
                "it is never written into the file."
            ),
            placeholder="a shared passphrase, e.g. team-p1-4-secret",
        )
        if not st.session_state.get("stego_key"):
            st.caption(
                "No stego key set — embedding and verification both need one."
            )


def _render_status() -> None:
    """Show which keys are loaded and their fingerprints."""
    kp = st.session_state.get("keypair")
    pub = st.session_state.get("public_key")

    left, right = st.columns(2)
    with left:
        if kp is None:
            st.caption("Private key: none loaded — you can verify but not embed")
        else:
            st.caption(f"Private key loaded · fingerprint `{kp.fingerprint}`")
    with right:
        if pub is None:
            st.caption("Public key: none loaded — verification unavailable")
        else:
            fp = crypto_utils.public_key_fingerprint(pub)
            source = st.session_state.get("public_key_source") or "unknown source"
            st.caption(f"Public key `{fp}` · {source}")

    # A mismatch is legitimate — it is exactly the wrong-key demo — so this is
    # information, not an error.
    if kp is not None and pub is not None:
        if crypto_utils.public_key_fingerprint(pub) != kp.fingerprint:
            st.info(
                "The loaded public key does not match the loaded private key. "
                "Anything signed here will verify as Signature Invalid.",
                icon=":material/info:",
            )


def _render_downloads() -> None:
    """Offer the loaded keys as PEM downloads."""
    kp = st.session_state.get("keypair")
    if kp is None:
        return

    left, right = st.columns(2)
    with left:
        st.download_button(
            "Download public key",
            data=crypto_utils.serialize_public_key(kp.public_key),
            file_name="public_key.pem",
            mime="application/x-pem-file",
            width="stretch",
        )
    with right:
        st.download_button(
            "Download private key",
            data=crypto_utils.serialize_private_key(kp.private_key),
            file_name="private_key_DEMO_ONLY.pem",
            mime="application/x-pem-file",
            width="stretch",
            help=(
                "Demo keys only. In a real deployment the private key never "
                "leaves the signer's machine."
            ),
        )
