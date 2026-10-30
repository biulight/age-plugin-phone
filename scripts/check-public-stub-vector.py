#!/usr/bin/env python3
"""Independent schema/Bech32 check of public stub expectations; stdlib only, no product encoder."""
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "crates/core/test-vectors"

def b64(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)

def header(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    for size, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if value < 1 << (8 * size):
            return bytes([(major << 5) | additional]) + value.to_bytes(size, "big")
    raise ValueError("integer too large")

def cbor(value):
    if isinstance(value, int):
        return header(0, value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return header(3, len(data)) + data
    return header(4, len(value)) + b"".join(cbor(item) for item in value)

def bech32(hrp, payload):
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    bits = "".join(f"{byte:08b}" for byte in payload)
    bits += "0" * (-len(bits) % 5)
    words = [int(bits[i:i+5], 2) for i in range(0, len(bits), 5)]
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + words + [0]*6
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> index) & 1:
                checksum ^= generator
    checksum ^= 1
    words += [(checksum >> (5*(5-i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(alphabet[word] for word in words)

def require(condition, label):
    if not condition:
        raise ValueError(label)

def check():
    p = json.loads((ROOT / "pairing-transcript-v2.json").read_text())
    v = json.loads((ROOT / "public-identity-stub-v2.json").read_text())
    # Independent P-256 scalar-3 public point, also used by the signed pairing fixture.
    phone = bytes.fromhex("025ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c")
    # Scalar 3 actually has an even Y coordinate; cross-check the existing recipient text.
    require(bech32("age1phone", b"\x01" + phone) == p["recipient"], "public stub expectation mismatch")
    selection = b64(p["desktop_selection_public_key_base64"])
    identity = bytes.fromhex(p["identity_id_hex"])
    fields = [2, 1, bytes.fromhex(p["desktop_id_hex"]), identity, p["recipient"],
              b64(p["desktop_signing_public_key_base64"]), selection,
              b64(p["phone_signing_public_key_base64"]), b64(p["offer_digest_base64"]),
              b64(p["fingerprint_base64"]), "phone"]
    encoded = cbor(fields)
    require(encoded == b64(v["stub_cbor_base64"]), "public stub expectation mismatch")
    require(bech32("age-plugin-phone-", encoded).upper() == v["plugin_identity"], "public stub expectation mismatch")
    require(bech32("age1phone", b"\x02" + phone + selection + identity) == v["phone_recipient"], "public stub expectation mismatch")
    require(bech32("age1tag", phone) == v["tag_recipient"], "public stub expectation mismatch")
    envelope = json.loads((ROOT / "phone-v2-envelope.json").read_text())
    require(envelope["recipient"] == v["phone_recipient"], "envelope/stub pairing mismatch")
    require(v["identity_file"] == f"# recipient: {v['phone_recipient']}\n# public age-plugin-phone identity stub\n{v['plugin_identity']}\n", "public stub expectation mismatch")
    print("Independent public stub CBOR, identity text and recipient expectations passed")

if __name__ == "__main__":
    check()
