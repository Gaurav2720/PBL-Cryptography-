#!/usr/bin/env python3
"""
crypto_utils.py - shared AES-256-GCM helpers
============================================

This module contains the cryptographic core used by every script in the
project:

    alice.py  (Terminal 1 - sender)
    bob.py    (Terminal 2 - receiver)
    main.py   (optional single-terminal demo)

Only the well-reviewed ``cryptography`` library performs AES. Nothing here
implements AES by hand. No function ever writes the shared key into the
message package.
"""

import base64
import binascii
import hashlib
import json
import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Constants

ALGORITHM = "AES-256-GCM"
KEY_SIZE = 32      # 32 bytes = 256 bits  -> AES-256
NONCE_SIZE = 12    # 12 bytes =  96 bits  -> recommended GCM nonce size
TAG_SIZE = 16      # 16 bytes = 128 bits  -> GCM authentication tag
KEY_FILE = Path(__file__).with_name("secret.key")
MESSAGE_FILE = Path(__file__).with_name("encrypted_message.json")
PACKAGE_VERSION = 1

# Width used to line up the labels in the terminal output.
LABEL_WIDTH = 28

# Used by the security tests when no message has been encrypted yet.
DEMO_PLAINTEXT = "Demo message for the security test."



# Key handling

def generate_key() -> bytes:
    """Return a fresh 256-bit key from the operating system's secure RNG.

    ``os.urandom`` is a cryptographically secure random generator, which is
    exactly what key material must come from. Never use ``random`` here.
    """
    return os.urandom(KEY_SIZE)


def save_key(key: bytes, path: Path = KEY_FILE) -> None:
    """Write the key to a local file as Base64 text."""
    path.write_text(base64.b64encode(key).decode("ascii"), encoding="ascii")

    # Best effort: restrict the file to the current user. On Windows the
    # read-only/owner bits mean little, so failures are ignored.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_key(path: Path = KEY_FILE) -> bytes:
    """Read the shared key file.

    Raises FileNotFoundError if the file is missing and ValueError if its
    contents are not a valid 32-byte Base64 key.
    """
    text = path.read_text(encoding="ascii").strip()

    try:
        key = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise ValueError("key file is not valid Base64") from exc

    if len(key) != KEY_SIZE:
        raise ValueError(
            f"key file must contain {KEY_SIZE} bytes, found {len(key)}"
        )
    return key


def key_fingerprint(key: bytes) -> str:
    """Short SHA-256 fingerprint of a key.

    Two people who think they share the same key can compare this value out
    loud. A fingerprint cannot be turned back into the key itself.
    """
    return hashlib.sha256(key).hexdigest()[:16]


def require_key() -> bytes | None:
    """Load the key or print a friendly error and return None."""
    try:
        return load_key()
    except FileNotFoundError:
        print(f"[FAIL] No key file found. Use option 1 to create {KEY_FILE.name}.")
    except (OSError, ValueError) as exc:
        print(f"[FAIL] Could not read the key file: {exc}")
    return None



# Encryption / decryption

def encrypt_message(key: bytes, plaintext: str) -> dict:
    """Encrypt ``plaintext`` with AES-256-GCM.

    Returns a dict with the raw ``nonce`` and ``ciphertext``. The library
    returns ciphertext with the 16-byte authentication tag appended to it;
    that combined blob is what gets stored and transmitted.

    A brand new random nonce is created for every single call. Reusing a
    nonce with the same key would break GCM's security completely.
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    # ``None`` is the optional associated data (AAD), which we do not use.
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """Decrypt and authenticate a message.

    Raises ``InvalidTag`` when the key is wrong or the nonce/ciphertext/tag
    was modified, and ``ValueError`` for malformed input. Plaintext is only
    returned after the authentication tag has been verified.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
    if len(ciphertext) < TAG_SIZE:
        raise ValueError("ciphertext is too short to contain a tag")

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")


def split_ciphertext(ciphertext: bytes) -> tuple[bytes, bytes]:
    """Split ``ciphertext || tag`` into the ciphertext body and the tag."""
    return ciphertext[:-TAG_SIZE], ciphertext[-TAG_SIZE:]


def flip_one_bit(data: bytes) -> bytes:
    """Return a copy of ``data`` with the lowest bit of the first byte flipped."""
    tampered = bytearray(data)
    tampered[0] ^= 0x01
    return bytes(tampered)



# Base64 and terminal output helpers

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_base64(text: str, label: str) -> bytes:
    """Decode Base64 input, raising a readable error for bad input."""
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValueError(f"{label} is empty")
    try:
        return base64.b64decode(cleaned, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"{label} is not valid Base64") from exc


def show_line(label: str, value: str) -> None:
    print(f"  {label:<{LABEL_WIDTH}}: {value}")


def show_block(label: str, value: str) -> None:
    """Print a long Base64 string on wrapped, indented lines."""
    print(f"  {label:<{LABEL_WIDTH}}:")
    for line in textwrap.wrap(value, width=64) or [""]:
        print(f"      {line}")


def show_package(nonce: bytes, ciphertext: bytes) -> None:
    """Display a transmitted package the way it would look on the wire."""
    body, tag = split_ciphertext(ciphertext)
    show_block("Nonce (96-bit, Base64)", to_base64(nonce))
    show_block("Ciphertext (Base64)", to_base64(ciphertext))
    show_block("Authentication tag (Base64)", to_base64(tag))
    show_line("Ciphertext length", f"{len(body)} bytes + {len(tag)}-byte tag")


def print_stage(number: int, title: str) -> None:
    """Print a numbered stage header: ``STAGE 1: KEY GENERATION``."""
    print("\n" + "=" * 62)
    print(f"  STAGE {number}: {title}")
    print("=" * 62)



# The file Alice sends to Bob

def write_message_package(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    plaintext_length: int,
    path: Path = MESSAGE_FILE,
) -> dict:
    """Save the encrypted package for Bob as JSON.

    The package contains the nonce, the ciphertext (with the tag appended)
    and display-friendly metadata. It deliberately does NOT contain the
    shared key: Alice and Bob exchange that separately through secret.key.
    """
    package = {
        "algorithm": ALGORITHM,
        "package_version": PACKAGE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sender": "Alice",
        "recipient": "Bob",
        "nonce": to_base64(nonce),
        "ciphertext": to_base64(ciphertext),
        "authentication_tag": to_base64(split_ciphertext(ciphertext)[1]),
        "plaintext_bytes": plaintext_length,
        # A short SHA-256 prefix so Bob can confirm he holds Alice's key.
        # A fingerprint cannot be turned back into the key itself.
        "key_fingerprint": key_fingerprint(key),
    }
    path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    return package


def read_message_package(path: Path = MESSAGE_FILE) -> dict:
    """Read and validate the package Bob received.

    Raises FileNotFoundError if Alice has not written the file yet, and
    ValueError with a readable message if the JSON or the Base64 fields are
    invalid. Returns raw bytes for the nonce and ciphertext.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("the package file is not valid UTF-8 text") from exc

    try:
        package = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("the package file is not valid JSON") from exc
    if not isinstance(package, dict):
        raise ValueError("the package file must contain a JSON object")

    if package.get("algorithm") != ALGORITHM:
        raise ValueError(f"package algorithm must be {ALGORITHM}")

    try:
        nonce = from_base64(str(package["nonce"]), "nonce")
        ciphertext = from_base64(str(package["ciphertext"]), "ciphertext")
    except KeyError as exc:
        raise ValueError(f"package is missing the field {exc}") from exc

    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, found {len(nonce)}")
    if len(ciphertext) < TAG_SIZE:
        raise ValueError("ciphertext is too short to contain a tag")

    # If the display copy of the tag is present, it must match the tag that
    # is really appended to the ciphertext. This only protects the JSON
    # metadata; the real integrity check happens during decryption.
    if "authentication_tag" in package:
        shown_tag = from_base64(
            str(package["authentication_tag"]), "authentication tag"
        )
        if shown_tag != split_ciphertext(ciphertext)[1]:
            raise ValueError(
                "the authentication_tag field does not match the ciphertext"
            )

    plaintext_bytes = package.get("plaintext_bytes")
    if not isinstance(plaintext_bytes, int) or isinstance(plaintext_bytes, bool):
        plaintext_bytes = None

    fingerprint = package.get("key_fingerprint")
    if not isinstance(fingerprint, str):
        fingerprint = None

    created_at = package.get("created_at")
    if not isinstance(created_at, str):
        created_at = None

    sender = package.get("sender")
    if not isinstance(sender, str):
        sender = None

    return {
        "path": path,
        "created_at": created_at,
        "sender": sender,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "plaintext_bytes": plaintext_bytes,
        "key_fingerprint": fingerprint,
    }
