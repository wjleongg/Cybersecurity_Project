"""The three payload sizes the brief asks to be demonstrated.

  short   one of the assignment's Learning Outcomes
  large   the assignment's Project Overview paragraph
  custom  whatever the team types, encrypted, to show confidentiality

Holding the exact texts here rather than typing them during the demo means the
short and large cases are reproducible, and the byte counts in the capacity
meter are the same every run.
"""

SHORT_MESSAGE = (
    "Explain how steganography can be used to embed hidden verification data "
    "in image and audio cover objects."
)

LARGE_MESSAGE = (
    "This undergraduate project requires student teams to design, implement and "
    "demonstrate a GUI-based LSB Replacement steganography program (window-based "
    "or web-based) that protects and verifies both image and audio cover objects "
    "using steganography, hashing and digital signatures. The project focuses on "
    "practical cybersecurity concepts: hiding a verification payload inside an "
    "image and an audio file, signing relevant verification data, extracting the "
    "hidden payload, checking the digital signature, and demonstrating positive "
    "and negative verification cases. Video as a cover object is not required for "
    "the main assignment, but may be attempted as an optional challenge."
)

CUSTOM_DEFAULT = (
    "Release approved for distribution on 2026-09-10. "
    "Internal reference INF2005-P1-4. Not for redistribution."
)

PRESETS = {
    "Short — a Learning Outcome": SHORT_MESSAGE,
    "Large — the Project Overview": LARGE_MESSAGE,
    "Custom — team-defined": CUSTOM_DEFAULT,
}
