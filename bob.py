#!/usr/bin/env python3
"""
bob.py - Terminal 2 (the receiver)
==================================

Bob does three things, in three clear stages:

    STAGE 3  MESSAGE TRANSFER  load the shared key and the package
    STAGE 4  DECRYPTION        verify the tag and recover the plaintext
    STAGE 5  SECURITY CHECK    prove the three protections still hold

If the authentication tag fails, Bob stops immediately and prints nothing
that looks like a decrypted message. AES-256-GCM never releases plaintext
that has not been authenticated.
"""

import sys

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    ALGORITHM,
    KEY_FILE,
    MESSAGE_FILE,
    decrypt_message,
    flip_one_bit,
    generate_key,
    key_fingerprint,
    load_key,
    print_stage,
    read_message_package,
    show_block,
    show_line,
    show_package,
    to_base64,
)

# Exit codes, so a script or a teacher can tell what happened.
EXIT_OK = 0
EXIT_SETUP = 1
EXIT_AUTH = 2
EXIT_TESTS = 3
EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def print_banner() -> None:
    print("=" * 62)
    print("  Secure Communication - AES-256-GCM")
    print("  TERMINAL 2 - BOB (receiver)")
    print("=" * 62)
    print("  Bob reads the shared key and the package that Alice wrote.")
    print("  Run alice.py in Terminal 1 first.")
    print(f"  Shared key file: {KEY_FILE.name}")
    print(f"  Package file  : {MESSAGE_FILE.name}")


# ---------------------------------------------------------------------------
# Stage 3 - message transfer (load key and package)
# ---------------------------------------------------------------------------
def receive_message() -> tuple[bytes, dict]:
    """Load the shared key and the encrypted package written by Alice."""
    print_stage(3, "MESSAGE TRANSFER")
    print("  Bob looks for the shared key and the encrypted package ...\n")

    try:
        key = load_key()
    except FileNotFoundError:
        print(f"  [FAIL] {KEY_FILE.name} not found in this folder.")
        print("  Run alice.py in Terminal 1 first, then copy secret.key here.")
        raise SystemExit(EXIT_SETUP)
    except (OSError, ValueError) as exc:
        print(f"  [FAIL] Could not read {KEY_FILE.name}: {exc}")
        raise SystemExit(EXIT_SETUP)

    show_line("Shared key file", KEY_FILE.name)
    show_line("Key fingerprint (local)", key_fingerprint(key))

    try:
        message = read_message_package()
    except FileNotFoundError:
        print(f"\n  [FAIL] {MESSAGE_FILE.name} not found in this folder.")
        print("  Run alice.py in Terminal 1 to create the package.")
        raise SystemExit(EXIT_SETUP)
    except (OSError, ValueError) as exc:
        print(f"\n  [FAIL] Could not read {MESSAGE_FILE.name}: {exc}")
        print("  Ask Alice to encrypt the message again.")
        raise SystemExit(EXIT_SETUP)

    print("\n  Package received:")
    show_line("Package file", message["path"].name)
    show_line("Sender", message["sender"] or "unknown")
    show_line("Created at", message["created_at"] or "unknown")
    if message["plaintext_bytes"] is not None:
        show_line("Plaintext size", f"{message['plaintext_bytes']} bytes")
    show_package(message["nonce"], message["ciphertext"])
    return key, message


# ---------------------------------------------------------------------------
# Stage 4 - decryption (Bob)
# ---------------------------------------------------------------------------
def decrypt_as_bob(key: bytes, message: dict) -> str:
    """Verify the authentication tag, then decrypt the message."""
    print_stage(4, "DECRYPTION \u2014 BOB")

    claimed = message["key_fingerprint"]
    local = key_fingerprint(key)
    show_line("Algorithm", ALGORITHM)
    show_line("Key fingerprint (package)", claimed or "not provided")
    show_line("Key fingerprint (local)", local)

    if claimed and claimed != local:
        print(
            "  [WARN] The package was encrypted with a different key.\n"
            "         The authentication check below will fail."
        )

    print("\n  Verifying the authentication tag and decrypting ...")

    try:
        plaintext = decrypt_message(
            key, message["nonce"], message["ciphertext"]
        )
    except InvalidTag:
        print("\n  [FAIL] Authentication failed.")
        print("  The key is wrong, or the nonce/ciphertext/tag was modified")
        print("  in transit. No plaintext is released when the tag fails.")
        print("\n  Ask Alice to check that you both use the same secret.key.")
        raise SystemExit(EXIT_AUTH)
    except ValueError as exc:
        print(f"\n  [FAIL] Malformed message: {exc}")
        raise SystemExit(EXIT_SETUP)

    print("  [PASS] Authentication tag verified with the shared key.")
    print("  [PASS] Decryption succeeded.")
    show_line("Recovered plaintext", plaintext)
    return plaintext


# ---------------------------------------------------------------------------
# Stage 5 - security verification
# ---------------------------------------------------------------------------
def run_security_tests(key: bytes, message: dict, plaintext: str) -> int:
    """Run the three classic checks and report how many passed."""
    print_stage(5, "SECURITY VERIFICATION")

    nonce = message["nonce"]
    ciphertext = message["ciphertext"]
    checks: list[bool] = []

    # Test 1: the correct key must work.
    print("  Test 1 - correct key must decrypt the message")
    try:
        result = decrypt_message(key, nonce, ciphertext)
    except (InvalidTag, ValueError) as exc:
        print(f"  [FAIL] The correct key was rejected ({type(exc).__name__}).")
        checks.append(False)
    else:
        if result == plaintext:
            print("  [PASS] Decryption succeeded and the plaintext matches.")
            checks.append(True)
        else:
            print("  [FAIL] Decryption succeeded but the plaintext differs.")
            checks.append(False)

    # Test 2: a different key must be rejected by the tag check.
    print("\n  Test 2 - incorrect key must be rejected")
    wrong_key = generate_key()
    show_line("Alice's key", f"fingerprint {key_fingerprint(key)}")
    show_line("Bob's wrong key", f"fingerprint {key_fingerprint(wrong_key)}")
    try:
        leak = decrypt_message(wrong_key, nonce, ciphertext)
    except InvalidTag:
        print("  [PASS] Rejected with InvalidTag; no plaintext was revealed.")
        checks.append(True)
    except ValueError as exc:
        print(f"  [PASS] Decryption failed: {exc}")
        checks.append(True)
    else:
        print(f"  [FAIL] The wrong key decrypted the message: {leak!r}")
        checks.append(False)

    # Test 3: one flipped bit in the ciphertext must be rejected.
    print("\n  Test 3 - modified ciphertext must be rejected")
    tampered = flip_one_bit(ciphertext)
    show_block("Original ciphertext (Base64)", to_base64(ciphertext))
    show_block("Tampered ciphertext (Base64)", to_base64(tampered))
    try:
        leak = decrypt_message(key, nonce, tampered)
    except InvalidTag:
        print("  [PASS] Rejected with InvalidTag; the tampering was detected.")
        checks.append(True)
    except ValueError as exc:
        print(f"  [PASS] Decryption failed: {exc}")
        checks.append(True)
    else:
        print(f"  [FAIL] The tampered ciphertext decrypted to: {leak!r}")
        checks.append(False)

    passed = sum(checks)
    print(f"\n  Result: {passed} of 3 security checks passed.")
    return passed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    print_banner()
    key, message = receive_message()
    plaintext = decrypt_as_bob(key, message)
    passed = run_security_tests(key, message, plaintext)
    if passed != 3:
        return EXIT_TESTS
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted. Goodbye.")
        sys.exit(EXIT_INTERRUPTED)
