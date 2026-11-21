#!/usr/bin/env python3
"""
Secure Communication Between Alice and Bob Using AES-256-GCM
============================================================

A small command-line demonstration of symmetric encryption:

    Alice --(plaintext)--> [AES-256-GCM + shared key] --> nonce + ciphertext
        ... insecure channel ...
    Bob   --(nonce + ciphertext)--> [AES-256-GCM + shared key] --> plaintext

The secret key is never sent with the message. Alice and Bob must obtain the
same 256-bit key through some secure channel beforehand. In this demo the key
is stored in the local file ``secret.key`` so both "sides" can use it.

Run with:  python main.py
"""

import base64
import binascii
import hashlib
import os
import sys
import textwrap
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALGORITHM = "AES-256-GCM"
KEY_SIZE = 32      # 32 bytes = 256 bits  -> AES-256
NONCE_SIZE = 12    # 12 bytes =  96 bits  -> recommended GCM nonce size
TAG_SIZE = 16      # 16 bytes = 128 bits  -> GCM authentication tag
KEY_FILE = Path(__file__).with_name("secret.key")

# Width used to line up the labels in the terminal output.
LABEL_WIDTH = 28

# Used by the two security tests when no message has been encrypted yet.
DEMO_PLAINTEXT = "Demo message for the security test."


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Small output helpers
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Menu actions - key generation
# ---------------------------------------------------------------------------
def action_generate_key() -> None:
    """Menu 1: create the shared 256-bit key."""
    print(f"\n[{ALGORITHM}] Generating a new 256-bit key ...")

    if KEY_FILE.exists():
        answer = input(
            f"  {KEY_FILE.name} already exists. Overwrite it? [y/N]: "
        ).strip().lower()
        if answer not in ("y", "yes"):
            print("  Cancelled; the existing key was kept.")
            return

    key = generate_key()
    save_key(key)

    print(f"  [OK] Key generated with os.urandom({KEY_SIZE}) (CSPRNG).")
    show_line("Key length", f"{len(key) * 8} bits")
    show_line("Key fingerprint", key_fingerprint(key))
    show_line("Saved to", KEY_FILE.name)
    print(
        "  Share this key with Bob only through a secure channel "
        "(in person, a password manager, or similar).\n"
        "  Never send it together with the ciphertext."
    )


# ---------------------------------------------------------------------------
# Menu actions - encryption (Alice)
# ---------------------------------------------------------------------------
def action_encrypt(state: dict) -> None:
    """Menu 2: Alice encrypts a message with the shared key."""
    key = require_key()
    if key is None:
        return

    plaintext = input("\nAlice's plaintext message: ")
    if not plaintext:
        print("[FAIL] The message is empty, nothing to encrypt.")
        return

    package = encrypt_message(key, plaintext)
    nonce, ciphertext = package["nonce"], package["ciphertext"]

    # Remember the last package so options 3-5 can reuse it.
    state["last_message"] = {
        "plaintext": plaintext,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }

    print("\n--- Alice: encryption result ---")
    show_line("Original plaintext", plaintext)
    show_line("Algorithm", ALGORITHM)
    show_package(nonce, ciphertext)
    print(
        "\n  Note: every encryption uses a fresh 96-bit nonce, so encrypting\n"
        "  the same message twice produces completely different output."
    )
    print(
        "\n  Simulating transmission to Bob over an insecure channel ...\n"
        "  Sent: nonce + ciphertext. The key stays with Alice."
    )


# ---------------------------------------------------------------------------
# Menu actions - decryption (Bob)
# ---------------------------------------------------------------------------
def action_decrypt(state: dict) -> None:
    """Menu 3: Bob decrypts what he received, using the same key."""
    key = require_key()
    if key is None:
        return

    last = state.get("last_message")
    print("\nBob received a nonce and a ciphertext (both Base64).")
    if last:
        print("Press Enter twice to reuse the message Alice just encrypted.")

    nonce_text = input("Nonce (Base64): ").strip()
    ciphertext_text = input("Ciphertext (Base64): ").strip()

    if last:
        nonce_text = nonce_text or to_base64(last["nonce"])
        ciphertext_text = ciphertext_text or to_base64(last["ciphertext"])
    elif not nonce_text or not ciphertext_text:
        print("[FAIL] Both the nonce and the ciphertext are required.")
        return

    try:
        nonce = from_base64(nonce_text, "nonce")
        ciphertext = from_base64(ciphertext_text, "ciphertext")
    except ValueError as exc:
        print(f"[FAIL] Invalid input: {exc}")
        return

    print("\n--- Bob: decryption result ---")
    show_line("Algorithm", ALGORITHM)

    try:
        plaintext = decrypt_message(key, nonce, ciphertext)
    except InvalidTag:
        print(
            "  [FAIL] Authentication failed: wrong key, or the nonce/"
            "ciphertext was modified."
        )
        print("  No plaintext is released when the tag does not verify.")
        return
    except ValueError as exc:
        print(f"  [FAIL] Malformed message: {exc}")
        return

    print("  [PASS] Authentication tag verified with the shared key.")
    print("  [PASS] Decryption succeeded.")
    show_line("Decrypted plaintext", plaintext)

    if last and plaintext == last["plaintext"]:
        print("  [PASS] Recovered plaintext matches Alice's original message.")


# ---------------------------------------------------------------------------
# Shared helper for the security tests
# ---------------------------------------------------------------------------
def get_test_message(state: dict, key: bytes) -> tuple[str, bytes, bytes]:
    """Return the last encrypted message, or encrypt a demo one."""
    last = state.get("last_message")
    if last:
        print(f"  Using the last message Alice encrypted: \"{last['plaintext']}\"")
        return last["plaintext"], last["nonce"], last["ciphertext"]

    package = encrypt_message(key, DEMO_PLAINTEXT)
    print(f"  No message yet - encrypting a demo message: \"{DEMO_PLAINTEXT}\"")
    return DEMO_PLAINTEXT, package["nonce"], package["ciphertext"]


# ---------------------------------------------------------------------------
# Menu actions - security test 2: incorrect key
# ---------------------------------------------------------------------------
def action_test_wrong_key(state: dict) -> None:
    """Menu 4: a different key must be rejected by the tag check."""
    key = require_key()
    if key is None:
        return

    print("\n--- Security test: incorrect key ---")
    _, nonce, ciphertext = get_test_message(state, key)

    wrong_key = generate_key()
    show_line(
        "Alice's key", f"{KEY_FILE.name} (fingerprint {key_fingerprint(key)})"
    )
    show_line(
        "Bob's wrong key",
        f"random key (fingerprint {key_fingerprint(wrong_key)})",
    )
    print("  Bob tries to decrypt with a key that is NOT Alice's key ...")

    try:
        leak = decrypt_message(wrong_key, nonce, ciphertext)
    except InvalidTag:
        print("  [PASS] Decryption failed with an authentication error (InvalidTag).")
        print("  [PASS] No plaintext was revealed to Bob.")
    except ValueError as exc:
        print(f"  [PASS] Decryption failed: {exc}")
    else:
        print(f"  [FAIL] Decryption succeeded with the wrong key: {leak!r}")
        print("  This must never happen with AES-256-GCM.")


# ---------------------------------------------------------------------------
# Menu actions - security test 3: ciphertext tampering
# ---------------------------------------------------------------------------
def action_test_tampering(state: dict) -> None:
    """Menu 5: a modified ciphertext must be rejected by the tag check."""
    key = require_key()
    if key is None:
        return

    print("\n--- Security test: ciphertext tampering ---")
    _, nonce, ciphertext = get_test_message(state, key)

    tampered = flip_one_bit(ciphertext)

    print("  An attacker flips one single bit of the ciphertext in transit.")
    show_block("Original ciphertext (Base64)", to_base64(ciphertext))
    show_block("Tampered ciphertext (Base64)", to_base64(tampered))

    try:
        leak = decrypt_message(key, nonce, tampered)
    except InvalidTag:
        print("  [PASS] Decryption failed with an authentication error (InvalidTag).")
        print("  [PASS] The tampering was detected and no plaintext was released.")
    except ValueError as exc:
        print(f"  [PASS] Decryption failed: {exc}")
    else:
        print(f"  [FAIL] Tampered ciphertext decrypted to: {leak!r}")
        print("  This must never happen with AES-256-GCM.")


# ---------------------------------------------------------------------------
# Terminal menu
# ---------------------------------------------------------------------------
def print_banner() -> None:
    print("=" * 62)
    print("  Secure Communication Between Alice and Bob")
    print("  Symmetric encryption with AES-256-GCM")
    print("=" * 62)
    print("  The message is protected by one shared 256-bit key.")
    print(f"  Shared key file: {KEY_FILE.name}")
    print("  Start with option 1 if no key exists yet.")


def print_menu() -> None:
    print("\n" + "-" * 62)
    print("  1. Generate Encryption Key")
    print("  2. Encrypt Message (Alice)")
    print("  3. Decrypt Message (Bob)")
    print("  4. Test Incorrect Key")
    print("  5. Test Ciphertext Tampering")
    print("  6. Exit")
    print("-" * 62)


def main() -> int:
    """Run the menu loop until the user chooses to exit."""
    print_banner()
    state: dict = {"last_message": None}

    while True:
        print_menu()
        choice = input("Choose an option [1-6]: ").strip()

        if choice == "1":
            action_generate_key()
        elif choice == "2":
            action_encrypt(state)
        elif choice == "3":
            action_decrypt(state)
        elif choice == "4":
            action_test_wrong_key(state)
        elif choice == "5":
            action_test_tampering(state)
        elif choice == "6":
            print("\nGoodbye. Keep the shared key secret.")
            return 0
        elif choice == "":
            print("[FAIL] No option entered. Please type a number from 1 to 6.")
        else:
            print(f"[FAIL] '{choice}' is not a valid option. Choose 1-6.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted. Goodbye.")
        sys.exit(130)
