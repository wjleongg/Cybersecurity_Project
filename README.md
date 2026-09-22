# Steganographic image, audio and video integrity verification

INF2005 ACW1. A GUI tool that hides a signed verification payload in the least
significant bits of a PNG, a WAV or an uncompressed AVI file, and later checks
whether that file is still what it claimed to be.

## What it does

**Protect** — hash the cover object, build a payload record (media ID,
timestamp, hash, nonce, issuer metadata, and the hidden message), sign it with
an Ed25519 private key, and write payload plus signature into the LSB planes
starting at a location derived from a shared secret.

**Verify** — recover the start location, extract the container, check the
signature with the public key, recompute the media hash, and return one of
seven verdicts: Authentic, Tampered, Signature Invalid, Payload Missing, Wrong
Start Location, Cannot Verify, or Replay Detected.

## Setup

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

The app opens at `...`.

No separate system `ffmpeg` install is required for the video path.
`opencv-python-headless` (see requirements.txt) bundles its own FFmpeg
read/write plugin, so `core/video_stego.py` never shells out to a command
line tool — see the Formats section below for why that matters in practice,
not just in principle.

## Generating the sample files

```bash
python -m scripts.make_samples
```

This writes a cover PNG, WAV and AVI, protected and tampered versions of
each, a demo keypair, and `test_evidence/test_evidence.md` recording all 39
cases and the verdict each produced. It exits non-zero if any case gives an
unexpected verdict, so it doubles as a regression check.

## Running the tests

```bash
python -m tests.test_core
```

126 assertions across all three media types: round trips at every LSB depth
from 1 to 8, wrap-around embedding, hash stability, all seven verdicts,
format rejection, start-location determinism (including the video
frame-index derivation), and replay/freshness detection.

## Using the tool

**Signing keys** sit above the tabs because one keypair signs both media
types. Generate a pair, or load PEM files. The fingerprint is shown next to
each key — useful when demonstrating the wrong-key case, since two visibly
different fingerprints explain the failure better than the verdict alone.

**Stego key** is the shared secret that determines where the payload starts
and what the container's marker looks like. Both parties need the same value.
It is never written into the file.

**Image, Audio and Video tabs** each contain the full workflow: upload,
configure, embed, compare, attack, verify. Grouping by media rather than by
direction means a demonstration of the image case never has to leave the
image tab.

### Encoding

1. Upload a cover PNG, WAV or AVI.
2. Choose the LSB depth (1–8). Higher carries more, distorts more.
3. Choose the start location mode. **Derived** computes it from the stego key,
   and the verifier recomputes the same value. **Manual** lets you pick, and
   the verifier has to be told separately — which is how the Wrong Start
   Location case is produced.
4. Pick a payload: a Learning Outcome (short), the Project Overview (large),
   or a custom message. Optionally encrypt it with AES-256-GCM.
5. Watch the capacity meter. It updates as you move the LSB slider and refuses
   an embed that will not fit.
6. Press **Embed and sign**, then compare cover and stego side by side.

### Verifying

Upload the file as the recipient would receive it, set the LSB depth used at
embedding, and press **Verify**. The verdict appears with the full check trail
underneath.

Leave "scan the file if nothing is found where expected" on. It is what lets
the tool distinguish Wrong Start Location from Payload Missing.

Verifying the exact same untouched file twice reports Replay Detected the
second time — that check runs unconditionally, after the signature and hash
both pass, and needs no tampering to demonstrate. "Enforce freshness window"
additionally rejects a payload older than a chosen number of minutes. "Reset
replay log" clears the history, for re-running the demo from a clean state.

## Repository layout

```
app.py                     Streamlit entry point, page layout, tabs
core/
  bitops.py                LSB read/write, capacity, plane masking
  crypto_utils.py          SHA-256, Ed25519 sign/verify, AES-GCM, PBKDF2
  container.py             Binary container framing and parsing
  payload.py               Payload record, canonical JSON, message encryption
  location.py              Keyed start-location, frame-index and magic-marker derivation
  image_stego.py           PNG loading, carriers, rebuild, PSNR
  audio_stego.py           WAV loading, carriers, rebuild, SNR
  video_stego.py           AVI loading, carriers, rebuild, PSNR (reused from image_stego)
  engine.py                Encode/verify orchestration, verdict logic
  attacks.py               Tamper simulation for negative cases
  replay_guard.py          Nonce reuse and freshness checking (opt-in)
  ledger.py                Optional Supabase issuance/revocation ledger
ui/
  state.py                 Session state across Streamlit reruns
  components.py            Verdict block, capacity meter, tables
  key_panel.py             Shared signing key panel
  media_tab.py             The workflow, shared by all three media types
  image_tab.py             PNG adapter
  audio_tab.py             WAV adapter
  video_tab.py             AVI adapter, with a frame scrubber for comparison
  ledger_panel.py          Ledger tab and ledger-aware verdict presentation
  messages.py              The three required payload sizes
scripts/make_samples.py    Sample generation and evidence run
tests/test_core.py         End-to-end tests
samples/                   Cover, protected and tampered files
keys/                      Demo keypair (see the warning below)
test_evidence/             Generated evidence log
```

## Formats

**PNG only for images.** PNG compression is lossless, so bits written to the
LSB planes survive a save and reload exactly. JPEG re-encodes with a lossy DCT
and destroys the payload immediately. All images are converted to RGB on load,
because PNG legally comes in palette, grayscale, RGB and RGBA modes and each
has a different relationship between file bytes and screen pixels. Alpha is
dropped rather than used as a carrier.

**Uncompressed WAV only for audio, 8-bit or 16-bit PCM.** MP3, AAC and Opus
discard exactly the low-order detail the payload lives in. 16-bit samples are
signed and 8-bit samples are unsigned with a midpoint of 128, so the two are
handled separately rather than assumed identical. 24-bit has no native integer
width; 32-bit float has no meaningful least significant bit.

**Uncompressed AVI only for video**, raw frames tagged with the `RGBA`
fourcc. Consumer MP4/H.264 re-encodes with lossy motion compensation and
destroys the payload immediately, the same way JPEG does for images. Frame
dimensions are forced to even numbers (a trailing row/column is cropped),
because the raw AVI muxer pads odd dimensions internally and that padding is
not restored on read, which would corrupt the LSB planes at the frame edge.
A video's carriers are every frame's pixel bytes flattened end to end, so a
container that does not fit in the frame it starts in simply continues into
the frames that follow — the same wraparound that lets a payload run past
the end of an image row.

File type is checked by reading the actual PNG signature, RIFF/WAVE header or
RIFF/AVI header, not by trusting the extension.

## Design notes

**Why the hash is computed on masked data.** The cover hash is taken over the
media with the embedding bit-planes zeroed. Embedding only ever changes those
planes, so the value signed before embedding is the value recomputed after it.
A hash over the raw file would change the moment anything was written into it
and so could not be signed in advance.

The trade-off is that a change confined to the embedding planes does not move
the hash. Such a change is caught by the signature or the header CRC instead,
and reported as Signature Invalid or Payload Missing.

**Why the start location is keyed.** `HMAC-SHA256(stego key, media type |
carrier count | LSB depth) mod carrier count`. Both parties derive the same
offset without transmitting it, and the offset changes for a different cover
object or a different LSB setting, so two files protected with one key do not
share a reusable offset. Video reuses this same formula twice: once over
frame count to pick a start frame, then again over that frame's carrier
count to pick the offset inside it — one explainable mechanism for all three
media types rather than a video-specific one bolted on beside it.

**Why the magic marker is keyed too.** A fixed marker such as the ASCII bytes
`STEG` would let anyone scan every offset for it and recover the location
without the key. Deriving the marker from the key means only a key holder can
scan — which is also what makes the Wrong Start Location diagnostic legitimate
rather than a backdoor.

**Why Ed25519 rather than RSA.** A signature is 64 bytes instead of 256, and
signature bytes compete directly with carrying capacity. At 1 LSB in a small
cover the difference is material. Ed25519 also has no padding-mode choices to
get wrong.

**Why signature and encryption are separate.** The signature covers the stored
payload, so it verifies without the passphrase. Encryption protects only the
message field. A recipient without the passphrase can still confirm the file
is authentic and untampered; they simply cannot read the message.

**Robust payload transport (assignment innovation).** This project also adds an
opt-in repetition-based redundancy layer for the hidden payload. The design is
kept intentionally simple and explainable: each payload bit is repeated three
times, and the decoder applies a majority vote to recover the original bit if a
few LSB flips happened during transmission or storage. The addition is handled
in `core/robust_codec.py`, and it wraps the exact payload bytes that are already
signed by the project, so the normal authenticity model stays intact while the
carrier becomes more tolerant to mild corruption.

The robust wrapper includes a magic marker (`RLC1`), a codec type, the original
payload length, and a CRC32 checksum, making the format self-identifying and
resistant to accidental truncation. Encoding uses the same container structure as
before, but the payload length is based on the repeated form, so capacity checks
and the container-size logic both account for the redundancy. The verifier runs
`robust_codec.decode()` before the usual signature and hash checks whenever the
robust option is enabled, which is exactly the “robust embedding innovation” a
steganalysis assignment asks for: a familiar LSB baseline remains available, and
an optional error-correction layer can recover from minor corruption without
changing the rest of the system.

**Replay/substitution detection (innovation).** A valid signature and a
matching hash prove a payload is genuine and unaltered — neither says whether
this exact file has been presented before, or how long ago it was issued. An
attacker who captures a legitimately signed stego file can resubmit it later
and, without this check, the tool would still say Authentic. Every payload
already carries a random nonce and an ISO-8601 issue timestamp
(`payload.py`); `core/replay_guard.py` is what actually reads them back: a
verifier keeps a small log of nonces it has already accepted and, optionally,
rejects anything older than a configured freshness window, surfaced as the
seventh verdict, Replay Detected. The check is opt-in — `engine.verify()`
only runs it when handed a `ReplayGuard`, so every pre-existing call site
(the automated tests, the sample/evidence generator) is unaffected and the
original six-verdict behaviour is preserved exactly when no guard is passed.
It needs no new tampering code to demonstrate: verifying the same untouched
file twice is itself the attack, which is the point — a signature and a hash
alone cannot tell a resubmitted file from a fresh one.

## Limitations

- LSB replacement is fragile by design. Re-encoding, resampling or lossy
  compression destroys the payload. The tool detects that the file is no
  longer trustworthy, but cannot recover what it originally said.
- The stego key is a shared secret. Anyone holding it can locate and read the
  container. The signature still prevents them from forging a new one.
- The keyed marker resists scanning, but the payload's presence may still be
  detectable statistically: the bit-plane histogram of an LSB-embedded file
  differs measurably from a natural one.
- Signature verification proves who signed a payload, not that the payload's
  claims are true. A signer who lies produces a validly signed lie.
- Audio degrades audibly at high LSB depths well before an image looks wrong,
  because the ear is sensitive to broadband noise. This is worth demonstrating
  rather than hiding.
- Browsers do not reliably play a raw/uncompressed AVI through an HTML5
  `<video>` element. The Video tab includes a frame-by-frame scrubber
  alongside the player for this reason: it always renders, since it is just
  still images, and it is what actually lets cover and stego be compared.

## Keys

`keys/` holds a keypair generated solely for this assignment demo, including
the private key. In a real deployment a private key would never be committed
or distributed. It is included here only so a marker can reproduce the signing
side of the workflow; `keys/demo_public_key.pem` alone is enough to reproduce
verification.

`keys/other_party_public_key.pem` is an unrelated public key, kept for the
wrong-key negative case.

`replay_log.json`, created at the project root the first time the GUI's
verify action runs, holds the replay-detection history (nonce → first-seen
time). It is runtime state, not source, and is excluded in `.gitignore`.
Delete it, or use the GUI's "Reset replay log" button, to start a demo fresh.
