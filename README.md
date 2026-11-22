# Secure Communication Between Alice and Bob Using AES-256-GCM

A beginner-friendly Python command-line project that shows how two people — Alice and
Bob — can exchange a confidential message using **symmetric encryption** with
**AES-256-GCM**.

The project runs as **two independent programs in two terminals**:

| Terminal | Script | Role |
|:--------:|--------|------|
| 1 | `alice.py` | Sender — creates the shared key, encrypts a message, writes `encrypted_message.json` |
| 2 | `bob.py` | Receiver — loads the shared key, reads the package, verifies the tag, decrypts |

Only the **nonce** and the **ciphertext** travel over the insecure channel. The key
never leaves `secret.key`. The authentication tag proves the message really came from
someone holding Alice's key and was not modified on the way.

Bob also runs **three security checks** that prove the protections still hold: the
correct key works, a wrong key is rejected, and a tampered ciphertext is rejected.

---

## Table of contents

1. [Objective](#objective)
2. [Project structure](#project-structure)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Quick start (two terminals)](#quick-start-two-terminals)
6. [The five stages](#the-five-stages)
7. [What Alice writes to disk](#what-alice-writes-to-disk)
8. [Sample terminal output](#sample-terminal-output)
9. [How the code is organised](#how-the-code-is-organised)
10. [The three security checks](#the-three-security-checks)
11. [Core concepts explained](#core-concepts-explained)
12. [Error handling and exit codes](#error-handling-and-exit-codes)
13. [Security notes and limitations](#security-notes-and-limitations)
14. [Troubleshooting](#troubleshooting)
15. [Optional single-terminal demo](#optional-single-terminal-demo)
16. [References](#references)

---

## Objective

Demonstrate, in a way that is easy to follow, that:

- a single **shared key** can protect a message in both directions (symmetric encryption);
- **AES-256-GCM** provides both confidentiality and integrity/authenticity;
- a **new random nonce** is required for every encryption;
- the **authentication tag** detects a wrong key or any change to the ciphertext
  *before* any plaintext is released.

The program never implements AES itself — it uses the well-reviewed
[`cryptography`](https://cryptography.io/) library.

---

## Project structure

```
pbl/
├── alice.py                # Terminal 1 - sender   (Stages 1-3)
├── bob.py                  # Terminal 2 - receiver (Stages 3-5)
├── crypto_utils.py         # the single copy of all crypto + file helpers
├── main.py                 # optional single-terminal menu demo
├── requirements.txt        # third-party dependency
├── README.md               # this file
├── demo.txt                # step-by-step demo script with talking points
├── sample_output.txt       # a real recorded two-terminal session
├── secret.key              # created by alice.py (Base64 shared key - keep it secret!)
└── encrypted_message.json  # created by alice.py (the package Bob reads)
```

`crypto_utils.py` is the **single source of truth**. `alice.py`, `bob.py`, and
`main.py` all import from it, so the AES code exists in exactly one place.

`secret.key` and `encrypted_message.json` do **not** ship with the project — they are
created the first time you run `alice.py`.

---

## Requirements

- **Python 3.10 or newer**
  (the code uses the `bytes | None` type syntax; tested on Python 3.14.6)
- The [`cryptography`](https://pypi.org/project/cryptography/) package
  (`>=42.0`, tested with 50.0.2)
- A terminal — this is a CLI program only. No GUI, no web server, no database.

Check your Python version:

```bash
python --version
```

---

## Installation

### 1. Open a terminal in the project folder

```powershell
cd path\to\pbl
```

### 2. (Recommended) create and activate a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install the dependency

```bash
pip install -r requirements.txt
```

`requirements.txt` contains:

```
cryptography>=42.0
```

---

## Quick start (two terminals)

Open **two** terminal windows, both in the project folder.

**Terminal 1 — Alice**

```bash
python alice.py
```

- Stage 1 creates `secret.key` (or reuses it if it already exists).
- Stage 2 asks for a message and encrypts it.
- Stage 3 writes `encrypted_message.json` and prints
  `Message encrypted and ready for Bob.`

**Terminal 2 — Bob**

```bash
python bob.py
```

- Stage 3 loads `secret.key` and the package.
- Stage 4 verifies the tag and prints the plaintext.
- Stage 5 runs the three security checks.

On macOS/Linux use `python3` instead of `python`.

> **Important:** both terminals must be in the same folder, because both scripts look
> for `secret.key` and `encrypted_message.json` **next to the script file**, not in the
> current working directory. You can therefore also run them from anywhere with
> `python path/to/pbl/alice.py`.

If you change the message, just run `alice.py` again, then `bob.py` again. If you
regenerate the key, Bob must get the **new** `secret.key` or decryption will fail.

---

## The five stages

Both scripts print numbered stage headers. Alice covers 1–3, Bob covers 3–5.

```
==============================================================
  STAGE 1: KEY GENERATION
==============================================================
  ...
==============================================================
  STAGE 2: ENCRYPTION — ALICE
==============================================================
  ...
==============================================================
  STAGE 3: MESSAGE TRANSFER
==============================================================
  ...
==============================================================
  STAGE 4: DECRYPTION — BOB
==============================================================
  ...
==============================================================
  STAGE 5: SECURITY VERIFICATION
==============================================================
  ...
```

| Stage | Script | What happens |
|:-----:|--------|--------------|
| **1. KEY GENERATION** | `alice.py` | Creates a fresh 256-bit key with `os.urandom(32)` and saves it to `secret.key` as Base64. If the file already exists, Alice asks whether to keep it (default) or replace it. |
| **2. ENCRYPTION — ALICE** | `alice.py` | Prompts for the plaintext, creates a **new 96-bit nonce**, encrypts with AES-256-GCM, and shows the plaintext, nonce, ciphertext and tag. |
| **3. MESSAGE TRANSFER** | `alice.py` then `bob.py` | Alice writes `encrypted_message.json`; Bob loads `secret.key` and that package and displays what he received. |
| **4. DECRYPTION — BOB** | `bob.py` | Compares the key fingerprint, verifies the authentication tag, and only then prints the plaintext. On failure it stops with an authentication error and releases nothing. |
| **5. SECURITY VERIFICATION** | `bob.py` | Runs the three security checks and prints `Result: N of 3 security checks passed.` |

### Why the nonce is always new

`encrypt_message()` calls `os.urandom(12)` on **every** call. Encrypting the same
message twice therefore produces different output, which the demo makes visible.

---

## What Alice writes to disk

`encrypted_message.json` is the package Bob reads:

```json
{
  "algorithm": "AES-256-GCM",
  "package_version": 1,
  "created_at": "2026-11-22T09:34:54+00:00",
  "sender": "Alice",
  "recipient": "Bob",
  "nonce": "869johMRYgTBa00r",
  "ciphertext": "uIsIylJ/sIL3hTNxxjy9Ju1/nzPSWUZQlZbV4lngAmXInfuRbwyG/y1VIBQOG14=",
  "authentication_tag": "Zcid+5FvDIb/LVUgFA4bXg==",
  "plaintext_bytes": 31,
  "key_fingerprint": "245d12d462970acc"
}
```

| Field | Meaning |
|-------|---------|
| `nonce` | The fresh 96-bit nonce, Base64. Not secret. |
| `ciphertext` | The ciphertext **with** the 16-byte tag appended, Base64. |
| `authentication_tag` | The same tag on its own, for display. Bob checks it matches the ciphertext. |
| `key_fingerprint` | First 16 hex chars of `SHA-256(key)`. Lets Bob confirm he holds Alice's key. A fingerprint cannot be turned back into the key. |
| `plaintext_bytes` | Length of the original message, in bytes. |
| `created_at`, `sender`, `recipient`, `algorithm`, `package_version` | Metadata for display and validation. |

**The shared key is never in this file.** There is no `key` field, and the fingerprint
is a one-way hash, not the key.

`bob.py` validates the package before using it: it must be valid UTF-8 JSON, a JSON
object, the right algorithm, valid Base64, a 12-byte nonce, at least a 16-byte
ciphertext, and — if present — an `authentication_tag` that matches the tag appended
to the ciphertext. Anything else produces a clear `[FAIL]` message and exit code 1.

---

## Sample terminal output

The transcript below is from a real run (also saved in
[`sample_output.txt`](sample_output.txt)). Base64 values are random on every run, so
yours will differ; the wording will be the same.

### Terminal 1 — Alice

```text
==============================================================
  Secure Communication - AES-256-GCM
  TERMINAL 1 - ALICE (sender)
==============================================================
  Alice encrypts a private message and writes the package
  file that Bob will open with bob.py in a second terminal.
  Shared key file: secret.key
  Package file  : encrypted_message.json

==============================================================
  STAGE 1: KEY GENERATION
==============================================================
  No secret.key yet, creating one now.
  [OK] Generating a 256-bit key with os.urandom(32) (CSPRNG).
  Key length                  : 256 bits
  Key fingerprint             : 245d12d462970acc
  Saved to                    : secret.key
  Give secret.key to Bob through a secure channel - in person, a
  password manager, or similar. Never send it with the ciphertext.

==============================================================
  STAGE 2: ENCRYPTION — ALICE
==============================================================
  Type the message Alice wants to send to Bob.
  It is encrypted before anything is written to disk.

  Plaintext message: Meet me at the library at 5 PM.

  Encryption result:
  Algorithm                   : AES-256-GCM
  Original plaintext          : Meet me at the library at 5 PM.
  Nonce (96-bit, Base64)      :
      869johMRYgTBa00r
  Ciphertext (Base64)         :
      uIsIylJ/sIL3hTNxxjy9Ju1/nzPSWUZQlZbV4lngAmXInfuRbwyG/y1VIBQOG14=
  Authentication tag (Base64) :
      Zcid+5FvDIb/LVUgFA4bXg==
  Ciphertext length           : 31 bytes + 16-byte tag

  Every encryption uses a fresh 96-bit nonce, so the same message
  encrypted twice never produces the same output.

==============================================================
  STAGE 3: MESSAGE TRANSFER
==============================================================
  Alice writes the encrypted package for Bob:
  Package file                : encrypted_message.json
  Sender                      : Alice
  Recipient                   : Bob
  Contents                    : nonce + ciphertext + authentication tag
  Secret key inside package   : no - it stays in secret.key
  Key fingerprint (for Bob)   : 245d12d462970acc

Message encrypted and ready for Bob.
Next: open Terminal 2 and run   python bob.py
```

### Terminal 2 — Bob

```text
==============================================================
  Secure Communication - AES-256-GCM
  TERMINAL 2 - BOB (receiver)
==============================================================
  Bob reads the shared key and the package that Alice wrote.
  Run alice.py in Terminal 1 first.
  Shared key file: secret.key
  Package file  : encrypted_message.json

==============================================================
  STAGE 3: MESSAGE TRANSFER
==============================================================
  Bob looks for the shared key and the encrypted package ...

  Shared key file             : secret.key
  Key fingerprint (local)     : 245d12d462970acc

  Package received:
  Package file                : encrypted_message.json
  Sender                      : Alice
  Created at                  : 2026-11-22T09:34:54+00:00
  Plaintext size              : 31 bytes
  Nonce (96-bit, Base64)      :
      869johMRYgTBa00r
  Ciphertext (Base64)         :
      uIsIylJ/sIL3hTNxxjy9Ju1/nzPSWUZQlZbV4lngAmXInfuRbwyG/y1VIBQOG14=
  Authentication tag (Base64) :
      Zcid+5FvDIb/LVUgFA4bXg==
  Ciphertext length           : 31 bytes + 16-byte tag

==============================================================
  STAGE 4: DECRYPTION — BOB
==============================================================
  Algorithm                   : AES-256-GCM
  Key fingerprint (package)   : 245d12d462970acc
  Key fingerprint (local)     : 245d12d462970acc

  Verifying the authentication tag and decrypting ...
  [PASS] Authentication tag verified with the shared key.
  [PASS] Decryption succeeded.
  Recovered plaintext         : Meet me at the library at 5 PM.

==============================================================
  STAGE 5: SECURITY VERIFICATION
==============================================================
  Test 1 - correct key must decrypt the message
  [PASS] Decryption succeeded and the plaintext matches.

  Test 2 - incorrect key must be rejected
  Alice's key                 : fingerprint 245d12d462970acc
  Bob's wrong key             : fingerprint 5b2f0e71c9c4a8dd
  [PASS] Rejected with InvalidTag; no plaintext was revealed.

  Test 3 - modified ciphertext must be rejected
  Original ciphertext (Base64):
      uIsIylJ/sIL3hTNxxjy9Ju1/nzPSWUZQlZbV4lngAmXInfuRbwyG/y1VIBQOG14=
  Tampered ciphertext (Base64):
      uYsIylJ/sIL3hTNxxjy9Ju1/nzPSWUZQlZbV4lngAmXInfuRbwyG/y1VIBQOG14=
  [PASS] Rejected with InvalidTag; the tampering was detected.

  Result: 3 of 3 security checks passed.
```

> Notice the two ciphertexts in Test 3 differ in exactly one character:
> `uIsI...` became `uYsI...`. One flipped bit is enough to make GCM reject the whole
> message.

---

## How the code is organised

### Data flow for one message

```
                secret.key (256-bit, shared in advance)
                        |                    |
                        v                    v
  Alice: plaintext --> AES-256-GCM encrypt --> nonce + (ciphertext || tag)
                              |
                              |  insecure channel: encrypted_message.json
                              |  (nonce + ciphertext + tag, never the key)
                              v
  Bob:   nonce + (ciphertext || tag) --> AES-256-GCM decrypt --> plaintext
                              ^
                        same secret.key
```

The key is **never** transmitted. If the tag does not verify, the library raises an
exception and Bob gets **no plaintext at all** — not even a partial or corrupted one.

### Function map (`crypto_utils.py`)

| Area | Function | Purpose |
|------|----------|---------|
| Key handling | `generate_key()` | 32 random bytes from `os.urandom` (a CSPRNG). |
| | `save_key()` / `load_key()` | Store/read the key as Base64 in `secret.key`; validates a 32-byte key. |
| | `key_fingerprint()` | First 16 hex chars of `SHA-256(key)`, for comparing keys safely. |
| | `require_key()` | Load the key or print a friendly error (used by `main.py`). |
| Crypto | `encrypt_message()` | New nonce, then `AESGCM(key).encrypt(nonce, plaintext, None)`. |
| | `decrypt_message()` | Validates sizes, then `AESGCM(key).decrypt(...)`; raises `InvalidTag` on failure. |
| | `split_ciphertext()` | Splits the library's `ciphertext || tag` into body and 16-byte tag. |
| | `flip_one_bit()` | Flips the lowest bit of byte 0 for the tampering check. |
| Package I/O | `write_message_package()` | Builds and writes `encrypted_message.json` (never includes the key). |
| | `read_message_package()` | Reads and validates the package, returning raw bytes. |
| Output | `show_line()` / `show_block()` / `show_package()` / `print_stage()` | Aligned, wrapped terminal output. |
| Base64 | `to_base64()` / `from_base64()` | Encode/decode with readable errors for bad input. |

### Script responsibilities

| Script | Owns |
|--------|------|
| `alice.py` | Banner, Stage 1 (create/reuse key), Stage 2 (prompt + encrypt + display), Stage 3 (write package + ready message). |
| `bob.py` | Banner, Stage 3 (load key + package + display), Stage 4 (fingerprint compare + decrypt), Stage 5 (three checks + result). |
| `main.py` | Optional single-terminal menu demo; imports the same crypto. |

### Important parameters

| Constant | Value | Meaning |
|----------|-------|---------|
| `KEY_SIZE` | 32 bytes | 256 bits → AES-256 |
| `NONCE_SIZE` | 12 bytes | 96 bits → the nonce size recommended for GCM |
| `TAG_SIZE` | 16 bytes | 128-bit authentication tag |
| `PACKAGE_VERSION` | 1 | Version of the JSON package format |

---

## The three security checks

Bob runs all three in Stage 5, using the message he just received.

### Check 1 — Correct key must decrypt

Bob decrypts with the same key Alice used. The tag verifies, decryption succeeds, and
the program confirms the plaintext matches.

```text
  [PASS] Decryption succeeded and the plaintext matches.
```

### Check 2 — Incorrect key must be rejected

A completely new random 256-bit key is generated. Because GCM's tag is derived from
the key, the nonce and the ciphertext, verification fails and `InvalidTag` is raised:

```text
  [PASS] Rejected with InvalidTag; no plaintext was revealed.
```

The key fingerprints are printed so you can see the two keys really are different
without exposing either key.

### Check 3 — Modified ciphertext must be rejected

The lowest bit of the first ciphertext byte is flipped. The nonce stays the same, only
one bit changes, yet authentication fails:

```text
  [PASS] Rejected with InvalidTag; the tampering was detected.
```

At the end Bob prints:

```text
  Result: 3 of 3 security checks passed.
```

If any check fails (which should never happen), Bob exits with code **3**.

---

## Core concepts explained

### Symmetric encryption

One single key is used both to encrypt and to decrypt. It is fast and ideal for
bulk data, but Alice and Bob must already share the key over a channel an attacker
cannot read. (That key-exchange problem is what asymmetric cryptography, e.g.
RSA or Diffie–Hellman, solves — it is out of scope here.)

### AES-256

The Advanced Encryption Standard with a 256-bit key. It is a block cipher that
scrambles data in a way that is reversible only with the key. Trying all 2²⁵⁶
keys is computationally infeasible.

### GCM (Galois/Counter Mode)

A mode of operation that turns AES into an **AEAD** cipher — Authenticated
Encryption with Associated Data. It provides:

- **Confidentiality** — nobody without the key can read the message.
- **Integrity and authenticity** — any change to the ciphertext, nonce, or tag is
  detected, and a successful decryption proves the sender knew the key.

GCM's guarantee is all-or-nothing: decryption either returns the exact plaintext
or fails. There is no "mostly correct but slightly wrong" output.

### Nonce

A **n**umber used **once**. Here it is 96 random bits, generated fresh for every
encryption and sent alongside the ciphertext (it is not secret). A unique nonce
ensures that encrypting the same message twice produces completely different
ciphertext.

> ⚠️ **Never reuse a nonce with the same key.** In GCM, a repeated nonce can leak
> the XOR of two plaintexts and can allow an attacker to forge the authentication
> tag, destroying both confidentiality and integrity. This program always calls
> `os.urandom(12)` inside `encrypt_message()`, so every encryption gets a new one.

### Authentication tag

A 128-bit value computed from the key, the nonce and the ciphertext. It is stored
with the ciphertext (the `cryptography` library appends it, giving
`ciphertext || tag`). Bob recomputes it during decryption; if the values differ,
the library raises `InvalidTag` and returns no plaintext. The tag is not a
signature — it only proves knowledge of the shared key.

### Base64

Ciphertext, nonces and tags are raw bytes, but the program prints them as Base64
text (and stores them that way in the JSON) so they are easy to copy and paste.
Base64 is **only** an encoding — it adds no security whatsoever. It is reversible by
anyone.

---

## Error handling and exit codes

Every script fails with a clear message instead of a traceback.

| Situation | Script | Message (example) | Exit |
|-----------|:------:|-------------------|:----:|
| Success | both | normal output | **0** |
| Empty message | Alice | `[FAIL] The message is empty, there is nothing to encrypt.` | **1** |
| `secret.key` missing / unreadable | Alice, Bob | `[FAIL] secret.key not found in this folder.` | **1** |
| Package missing | Bob | `[FAIL] encrypted_message.json not found in this folder.` | **1** |
| Invalid JSON / wrong algorithm / bad Base64 / bad lengths / tag mismatch | Bob | `[FAIL] Could not read encrypted_message.json: ...` | **1** |
| Wrong key or modified ciphertext | Bob | `[FAIL] Authentication failed.` + explanation | **2** |
| A security check failed (should not happen) | Bob | `Result: N of 3 security checks passed.` | **3** |
| `Ctrl+C` / closed input | both | `Interrupted. Goodbye.` | **130** |

When Bob hits an authentication failure in Stage 4 he stops there (exit **2**) and
does **not** run Stage 5.

Alice also refuses to overwrite a package if the message is empty, so an earlier good
package is never destroyed by a bad run.

---

## Security notes and limitations

This is a teaching demo, not a production messaging system.

- **The key file is a demo shortcut.** `secret.key` sits next to the script
  (restricted to the current user with `chmod 0o600` where the OS supports it).
  In real life, keys belong in a key store / HSM and must be exchanged out of band.
  Never commit `secret.key` to Git or share it in chat or email.
- **No key exchange.** Alice and Bob are assumed to already share the key. There is
  no Diffie–Hellman, RSA, certificates or password-based key derivation.
- **No password-based KDF.** The key is fully random, not derived from a
  passphrase with scrypt/PBKDF2/Argon2.
- **No AAD.** The program passes `None` for associated data. A real protocol would
  authenticate metadata (sender, recipient, message number, protocol version).
- **No replay protection.** An attacker who records a valid package cannot read or
  alter it, but can resend it later. Real protocols use counters, timestamps or
  sequence numbers.
- **No forward secrecy.** If the long-term key leaks, previously recorded traffic
  can be decrypted. Ephemeral key exchange prevents that.
- **Ciphertext length is visible.** Encryption hides the content, not the size or
  the timing of messages.
- **A single package file.** `encrypted_message.json` holds only the most recent
  message; a real system would have a message format with IDs and ordering.
- **Terminal output is a teaching aid,** not a wire format. In a real system the
  nonce and ciphertext would be sent as bytes with a defined message layout.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'cryptography'` | Dependency not installed, or the virtual environment is not activated. | `pip install -r requirements.txt` |
| Alice: `[FAIL] secret.key exists but cannot be used: ...` | The key file was edited or truncated. | Delete `secret.key` and run `alice.py` again. |
| Bob: `[FAIL] secret.key not found in this folder.` | Bob has no key, or the terminals are in different folders. | Run `alice.py` first, or copy `secret.key` next to `bob.py`. |
| Bob: `[FAIL] encrypted_message.json not found in this folder.` | Alice has not run yet. | Run `alice.py` in Terminal 1. |
| Bob: `[FAIL] Authentication failed.` (exit 2) | Wrong key, or the package was altered. | Make sure Bob has the **same** `secret.key` Alice used; re-run `alice.py` if needed. |
| Bob: `[FAIL] Could not read encrypted_message.json: the authentication_tag field does not match the ciphertext` | The JSON was hand-edited. | Re-run `alice.py`. |
| `SyntaxError` on Python 3.9 or older | The code uses `bytes | None`. | Use Python 3.10+ (or newer). |
| Different output every run | Expected: nonces are random. | Nothing to fix — this is correct behaviour. |
| Replacing the key breaks Bob | Bob still has the old key. | Give Bob the new `secret.key`. |

To regenerate `sample_output.txt`, see [`demo.txt`](demo.txt) for the exact steps.

---

## Optional single-terminal demo

`main.py` is a menu-driven version that runs Alice and Bob in **one** window. It uses
the same `crypto_utils.py` code, so nothing about the cryptography changes.

```bash
python main.py
```

| Option | Name | What it does |
|:------:|------|--------------|
| **1** | Generate Encryption Key | Creates `secret.key`. |
| **2** | Encrypt Message (Alice) | Encrypts a message and remembers it. |
| **3** | Decrypt Message (Bob) | Press **Enter** twice to reuse the last message. |
| **4** | Test Incorrect Key | Tries a different random key; the tag check fails. |
| **5** | Test Ciphertext Tampering | Flips one bit; the tag check fails. |
| **6** | Exit | Leaves the program. |

Use `alice.py` and `bob.py` when you want to demonstrate the two-party workflow in
two real terminals. Use `main.py` for a quick single-window walkthrough.

---

## References

- **NIST SP 800-38D** — *Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM) and GMAC*:
  <https://csrc.nist.gov/pubs/sp/800/38/d/final>
- **NIST FIPS 197** — *Advanced Encryption Standard (AES)*:
  <https://csrc.nist.gov/pubs/fips/197/final>
- **`cryptography` documentation — AES-GCM**:
  <https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM>
- **Python `os.urandom`**:
  <https://docs.python.org/3/library/os.html#os.urandom>
- **OWASP Cryptographic Storage Cheat Sheet** — practical guidance on key
  management, nonces and authenticated encryption:
  <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

---

*Educational project — Cryptography, Semester 5.*
