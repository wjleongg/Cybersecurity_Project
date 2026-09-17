"""INF2005 ACW1 — steganographic integrity verifier.

Entry point. Run with:

    streamlit run app.py

Layout follows the workflow rather than the code structure: a shared key panel
above, then one tab per cover object, and inside each tab the sequence
upload -> configure -> embed -> compare -> attack -> verify. Grouping by media
rather than by direction means a demonstration of the image case never has to
leave the image tab.
"""

import streamlit as st

st.set_page_config(
    page_title="Stego integrity verifier",
    page_icon=":material/shield_lock:",
    layout="wide",
)

from ui import audio_tab, image_tab, key_panel, state  # noqa: E402


def main() -> None:
    state.init()

    with st.container(border=True):
        st.markdown("### Steganographic image and audio integrity verification")
        st.caption(
            "LSB replacement with Ed25519-signed verification payloads and "
            "keyed start locations · INF2005 ACW1"
        )

    key_panel.render()
    st.write("")

    tab_image, tab_audio, tab_about = st.tabs(
        ["Image (PNG)", "Audio (WAV)", "How it works"]
    )

    with tab_image:
        image_tab.render()

    with tab_audio:
        audio_tab.render()

    with tab_about:
        _render_about()


def _render_about() -> None:
    """A reference page for the demo, so nothing has to be recited from memory."""
    st.markdown(
        """
#### What gets embedded

A container is written into the least significant bits of the cover object:

| Field | Size | Purpose |
| --- | --- | --- |
| Magic marker | 4 bytes | Keyed, so only a stego-key holder can recognise a container |
| Version, flags, length | 6 bytes | Format version and payload size |
| Header CRC | 4 bytes | Rejects a misread header before it can be acted on |
| Payload | variable | Canonical JSON: media ID, timestamp, cover hash, nonce, issuer, LSB depth, message |
| Signature | 64 bytes | Ed25519 over version, flags, length and payload |

#### How the start location works

The payload does not start at carrier zero. Its position is
`HMAC-SHA256(stego key, media type | carrier count | LSB depth) mod carrier count`.
Both parties derive the same offset from the shared key without ever
transmitting it, and the offset changes for a different cover object or a
different LSB setting.

The container's magic marker is derived from the same key. A fixed marker
would let anyone scan every offset for it and find the payload without the
key, which would make the whole scheme decorative.

#### Why the hash is computed on masked data

The cover hash is taken over the media with the embedding bit-planes zeroed.
Embedding only ever changes those planes, so the value signed before embedding
is the value recomputed after it. A hash over the raw file would change the
moment anything was written into it, and so could not be signed in advance.

The trade-off: a change confined to the embedding planes does not move the
hash. Such a change is caught by the signature or the header CRC instead, and
reported as Signature Invalid or Payload Missing.

#### How replay detection works

A valid signature and a matching hash only prove a payload is genuine and
unaltered — neither says anything about whether *this exact file* has been
presented before. Every payload already carries a random nonce and an
issue timestamp; the verifier keeps a log of nonces it has already accepted
and, optionally, rejects anything older than a configured window. Verifying
the same untouched, legitimately signed file twice produces Authentic the
first time and Replay Detected the second — no tampering required, because
the whole point is that a replay attack needs none.

#### Verdicts

| Verdict | Meaning |
| --- | --- |
| Authentic | Signature valid and the media hash matches the signed value |
| Tampered | Signature valid, but the media has changed since it was signed |
| Signature Invalid | A payload was found, but not signed by the loaded public key |
| Payload Missing | No container for this stego key anywhere in the file |
| Wrong Start Location | A container exists, but not where the verifier looked |
| Cannot Verify | The check could not be completed — missing key or unreadable input |
| Replay Detected | Signature and hash are both fine, but this exact payload was already verified before, or is older than the allowed freshness window |

#### Known limitations

- LSB replacement is fragile by design. Re-encoding, resampling or lossy
  compression destroys the payload. The tool detects that the file is no
  longer trustworthy, but cannot recover what it originally said.
- The stego key is a shared secret. Anyone holding it can locate and read the
  container; the signature still prevents them from forging a new one.
- The keyed marker resists scanning, but the payload's presence may still be
  detectable statistically — the bit-plane histogram of an LSB-embedded file
  differs from a natural one.
- Signature verification proves who signed a payload, not that the payload's
  claims are true. A signer who lies produces a validly signed lie.
"""
    )


if __name__ == "__main__":
    main()
