#!/usr/bin/env python3
"""
alice.py - Terminal 1 (the sender)
==================================

Alice does three things, in three clear stages:

    STAGE 1  KEY GENERATION    create or reuse the shared 256-bit key
    STAGE 2  ENCRYPTION        encrypt her plaintext with AES-256-GCM
    STAGE 3  MESSAGE TRANSFER  write the package to encrypted_message.json

Bob runs bob.py in a second terminal and reverses the process.

All cryptography lives in crypto_utils.py, which uses the well-reviewed
``cryptography`` library. Nothing here implements AES by hand, and the
secret key is never written into the message package.
"""

import sys

from crypto_utils import (
    ALGORITHM,
    KEY_FILE,
    KEY_SIZE,
    MESSAGE_FILE,
    encrypt_message,
    generate_key,
    key_fingerprint,
    load_key,
    print_stage,
    save_key,
    show_line,
    show_package,
    write_message_package,
)

# Exit codes, so a script or a teacher can tell what happened.
EXIT_OK = 0
EXIT_SETUP = 1
EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def print_banner() -> None:
    print("=" * 62)
    print("  Secure Communication - AES-256-GCM")
    print("  TERMINAL 1 - ALICE (sender)")
    print("=" * 62)
    print("  Alice encrypts a private message and writes the package")
    print("  file that Bob will open with bob.py in a second terminal.")
    print(f"  Shared key file: {KEY_FILE.name}")
    print(f"  Package file  : {MESSAGE_FILE.name}")


# ---------------------------------------------------------------------------
# Stage 1 - key generation
# ---------------------------------------------------------------------------
def prepare_key() -> bytes:
    """Create the shared key, or reuse the one already on disk.

    Reusing the existing key is the safe default: if Alice replaced it,
    Bob's copy would no longer match and every message would fail the
    authentication check.
    """
    print_stage(1, "KEY GENERATION")

    if KEY_FILE.exists():
        try:
            key = load_key()
        except (OSError, ValueError) as exc:
            print(f"  [FAIL] {KEY_FILE.name} exists but cannot be used: {exc}")
            print("  Delete or fix that file, then run alice.py again.")
            raise SystemExit(EXIT_SETUP)

        show_line("Existing key file", KEY_FILE.name)
        show_line("Key fingerprint", key_fingerprint(key))

        answer = input(
            f"  Generate a new key instead? Bob needs the same key. [y/N]: "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("  [OK] Keeping the existing shared key.")
            show_line("Key length", f"{len(key) * 8} bits")
            show_line("Key status", f"{KEY_FILE.name} unchanged")
            return key

        print(f"  [WARN] The old key is replaced; Bob must get the new key.")

    else:
        print(f"  No {KEY_FILE.name} yet, creating one now.")

    print(f"  [OK] Generating a 256-bit key with os.urandom({KEY_SIZE}) (CSPRNG).")
    key = generate_key()
    save_key(key)

    show_line("Key length", f"{len(key) * 8} bits")
    show_line("Key fingerprint", key_fingerprint(key))
    show_line("Saved to", KEY_FILE.name)
    print(
        "  Give secret.key to Bob through a secure channel - in person, a\n"
        "  password manager, or similar. Never send it with the ciphertext."
    )
    return key


# ---------------------------------------------------------------------------
# Stage 2 - encryption (Alice)
# ---------------------------------------------------------------------------
def encrypt_for_bob(key: bytes) -> tuple[str, bytes, bytes]:
    """Ask Alice for a message and encrypt it with a fresh nonce."""
    print_stage(2, "ENCRYPTION \u2014 ALICE")
    print("  Type the message Alice wants to send to Bob.")
    print("  It is encrypted before anything is written to disk.")

    plaintext = input("\n  Plaintext message: ")
    if not plaintext:
        print("  [FAIL] The message is empty, there is nothing to encrypt.")
        raise SystemExit(EXIT_SETUP)

    # encrypt_message() creates a brand new 96-bit random nonce every call.
    package = encrypt_message(key, plaintext)
    nonce = package["nonce"]
    ciphertext = package["ciphertext"]

    print("\n  Encryption result:")
    show_line("Algorithm", ALGORITHM)
    show_line("Original plaintext", plaintext)
    show_package(nonce, ciphertext)
    print(
        "\n  Every encryption uses a fresh 96-bit nonce, so the same message\n"
        "  encrypted twice never produces the same output."
    )
    return plaintext, nonce, ciphertext


# ---------------------------------------------------------------------------
# Stage 3 - message transfer (write the package)
# ---------------------------------------------------------------------------
def send_to_bob(
    key: bytes, plaintext: str, nonce: bytes, ciphertext: bytes
) -> None:
    """Write the package file Bob will read in the other terminal."""
    print_stage(3, "MESSAGE TRANSFER")

    write_message_package(
        key,
        nonce,
        ciphertext,
        len(plaintext.encode("utf-8")),
    )

    print("  Alice writes the encrypted package for Bob:")
    show_line("Package file", MESSAGE_FILE.name)
    show_line("Sender", "Alice")
    show_line("Recipient", "Bob")
    show_line("Contents", "nonce + ciphertext + authentication tag")
    show_line("Secret key inside package", "no - it stays in secret.key")
    show_line("Key fingerprint (for Bob)", key_fingerprint(key))
    print()
    print("Message encrypted and ready for Bob.")
    print("Next: open Terminal 2 and run   python bob.py")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    print_banner()
    key = prepare_key()
    plaintext, nonce, ciphertext = encrypt_for_bob(key)
    send_to_bob(key, plaintext, nonce, ciphertext)
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted. Goodbye.")
        sys.exit(EXIT_INTERRUPTED)
