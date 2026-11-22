#!/usr/bin/env python3
"""
main.py - optional single-terminal demo
=======================================

This menu-driven version runs Alice and Bob in one window. It uses exactly
the same AES-256-GCM code as alice.py and bob.py, imported from
crypto_utils.py, so there is only one implementation of the cryptography
in the project.

For the two-terminal workflow use alice.py (Terminal 1) and bob.py
(Terminal 2) instead.
"""

import sys

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    ALGORITHM,
    DEMO_PLAINTEXT,
    KEY_FILE,
    KEY_SIZE,
    decrypt_message,
    encrypt_message,
    flip_one_bit,
    from_base64,
    generate_key,
    key_fingerprint,
    load_key,
    require_key,
    save_key,
    show_block,
    show_line,
    show_package,
    to_base64,
)


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
