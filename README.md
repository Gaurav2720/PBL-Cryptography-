# Secure Communication Between Alice and Bob Using AES-256-GCM

A beginner-friendly Python command-line project that shows how two people — Alice and
Bob — can exchange a confidential message using **symmetric encryption** with
**AES-256-GCM**.

Alice encrypts a message with a shared 256-bit key. Only the **nonce** and the
**ciphertext** travel over the insecure channel. Bob, who holds the same key,
decrypts the message and the authentication tag proves that the message really
came from Alice and was not modified on the way.

The project also runs three security tests that show what happens when
someone uses the wrong key or tampers with the ciphertext.

---

## Table of contents

1. [Objective](#objective)
2. [Project structure](#project-structure)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [How to run](#how-to-run)
6. [Menu options](#menu-options)
7. [Sample terminal output](#sample-terminal-output)
8. [How the program works](#how-the-program-works)
9. [The three security tests](#the-three-security-tests)
10. [Core concepts explained](#core-concepts-explained)
11. [Security notes and limitations](#security-notes-and-limitations)
12. [Troubleshooting](#troubleshooting)
13. [References](#references)

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
├── main.py             # the whole program (menu + crypto + tests)
├── requirements.txt    # third-party dependency
├── README.md           # this file
├── sample_output.txt   # a real recorded terminal session
└── secret.key          # created at runtime (Base64 shared key - keep it secret!)
```

`secret.key` does **not** ship with the project. It is created the first time you
choose **option 1 (Generate Encryption Key)**.

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

## How to run

```bash
python main.py
```

On macOS/Linux you may need `python3 main.py`.

A quick first run:

1. Choose **1** to generate the shared key (`secret.key`).
2. Choose **2**, type a message, and read the nonce, ciphertext and tag.
3. Choose **3** and press **Enter twice** to decrypt the message you just sent.
4. Choose **4** and **5** to watch the two attacks fail.
5. Choose **6** to exit.

---

## Menu options

| Option | Name | What it does |
|:------:|------|--------------|
| **1** | Generate Encryption Key | Creates a fresh 256-bit key with `os.urandom(32)` and saves it to `secret.key` as Base64. Shows a short SHA-256 **fingerprint** so Alice and Bob can confirm they hold the same key. |
| **2** | Encrypt Message (Alice) | Reads a plaintext, creates a new 96-bit nonce, encrypts with AES-256-GCM, and prints the plaintext, algorithm, nonce, ciphertext, authentication tag and lengths. Then simulates sending `nonce + ciphertext` to Bob. |
| **3** | Decrypt Message (Bob) | Asks for the nonce and ciphertext (Base64). Pressing **Enter** for both reuses the message from option 2. Verifies the tag and prints the recovered plaintext, or an authentication error. |
| **4** | Test Incorrect Key | Encrypts a message, then tries to decrypt it with a **different random key**. The tag check fails with `InvalidTag`, so no plaintext leaks. |
| **5** | Test Ciphertext Tampering | Flips **one single bit** of the ciphertext (an active attacker in transit). The tag check fails and the tampering is detected. |
| **6** | Exit | Leaves the program. |

Invalid menu entries, empty messages, missing key files and malformed Base64 are
all handled with a clear `[FAIL] ...` message instead of a traceback.

---

## Sample terminal output

The transcript below is from a real run (also saved in
[`sample_output.txt`](sample_output.txt)). Base64 values are random on every run.

```text
==============================================================
  Secure Communication Between Alice and Bob
  Symmetric encryption with AES-256-GCM
==============================================================
  The message is protected by one shared 256-bit key.
  Shared key file: secret.key
  Start with option 1 if no key exists yet.

--------------------------------------------------------------
  1. Generate Encryption Key
  2. Encrypt Message (Alice)
  3. Decrypt Message (Bob)
  4. Test Incorrect Key
  5. Test Ciphertext Tampering
  6. Exit
--------------------------------------------------------------
Choose an option [1-6]: 1

[AES-256-GCM] Generating a new 256-bit key ...
  [OK] Key generated with os.urandom(32) (CSPRNG).
  Key length                  : 256 bits
  Key fingerprint             : 4da610d34cbab1c0
  Saved to                    : secret.key
  Share this key with Bob only through a secure channel (in person, a password manager, or similar).
  Never send it together with the ciphertext.

Choose an option [1-6]: 2

Alice's plaintext message: Meet me at the library at 5 PM.

--- Alice: encryption result ---
  Original plaintext          : Meet me at the library at 5 PM.
  Algorithm                   : AES-256-GCM
  Nonce (96-bit, Base64)      :
      tF0138Mg3q/9thdf
  Ciphertext (Base64)         :
      8ZIs6Ml1xZmpUsZ0T0gtJBJhyNmqxqOSsAQ6QO7yC1qQSV++8YfjZ2+2si45QLI=
  Authentication tag (Base64) :
      WpBJX77xh+Nnb7ayLjlAsg==
  Ciphertext length           : 31 bytes + 16-byte tag

  Note: every encryption uses a fresh 96-bit nonce, so encrypting
  the same message twice produces completely different output.

  Simulating transmission to Bob over an insecure channel ...
  Sent: nonce + ciphertext. The key stays with Alice.

Choose an option [1-6]: 3

Bob received a nonce and a ciphertext (both Base64).
Press Enter twice to reuse the message Alice just encrypted.
Nonce (Base64): 
Ciphertext (Base64): 

--- Bob: decryption result ---
  Algorithm                   : AES-256-GCM
  [PASS] Authentication tag verified with the shared key.
  [PASS] Decryption succeeded.
  Decrypted plaintext         : Meet me at the library at 5 PM.
  [PASS] Recovered plaintext matches Alice's original message.

Choose an option [1-6]: 4

--- Security test: incorrect key ---
  Using the last message Alice encrypted: "Meet me at the library at 5 PM."
  Alice's key                 : secret.key (fingerprint 4da610d34cbab1c0)
  Bob's wrong key             : random key (fingerprint 80deb7dc94f990f7)
  Bob tries to decrypt with a key that is NOT Alice's key ...
  [PASS] Decryption failed with an authentication error (InvalidTag).
  [PASS] No plaintext was revealed to Bob.

Choose an option [1-6]: 5

--- Security test: ciphertext tampering ---
  Using the last message Alice encrypted: "Meet me at the library at 5 PM."
  An attacker flips one single bit of the ciphertext in transit.
  Original ciphertext (Base64):
      8ZIs6Ml1xZmpUsZ0T0gtJBJhyNmqxqOSsAQ6QO7yC1qQSV++8YfjZ2+2si45QLI=
  Tampered ciphertext (Base64):
      8JIs6Ml1xZmpUsZ0T0gtJBJhyNmqxqOSsAQ6QO7yC1qQSV++8YfjZ2+2si45QLI=
  [PASS] Decryption failed with an authentication error (InvalidTag).
  [PASS] The tampering was detected and no plaintext was released.

Choose an option [1-6]: 6

Goodbye. Keep the shared key secret.
```

> Notice the two ciphertexts in the tampering test differ in exactly one
> character: `8ZIs6M...` became `8JIs6M...`. One flipped bit is enough to make
> GCM reject the whole message.

---

## How the program works

The data flow for one message:

```
                secret.key (256-bit, shared in advance)
                        |                    |
                        v                    v
  Alice: plaintext --> AES-256-GCM encrypt --> nonce + (ciphertext || tag)
                              |
                              |  insecure channel: nonce + ciphertext only
                              v
  Bob:   nonce + (ciphertext || tag) --> AES-256-GCM decrypt --> plaintext
                              ^
                        same secret.key
```

The key is **never** transmitted. Only the nonce and ciphertext cross the channel.
If the tag does not verify, the library raises an exception and Bob gets **no
plaintext at all** — not even a partial or corrupted one.

### Function map (`main.py`)

| Area | Function | Purpose |
|------|----------|---------|
| Key handling | `generate_key()` | 32 random bytes from `os.urandom` (a CSPRNG). |
| | `save_key()` / `load_key()` | Store/read the key as Base64 in `secret.key`; validates a 32-byte key. |
| | `key_fingerprint()` | First 16 hex chars of `SHA-256(key)`, for comparing keys safely. |
| | `require_key()` | Load the key or print a friendly error. |
| Crypto | `encrypt_message()` | New nonce, then `AESGCM(key).encrypt(nonce, plaintext, None)`. |
| | `decrypt_message()` | Validates sizes, then `AESGCM(key).decrypt(...)`; raises `InvalidTag` on failure. |
| | `split_ciphertext()` | Splits the library's `ciphertext || tag` into body and 16-byte tag for display. |
| | `flip_one_bit()` | Flips the lowest bit of byte 0 for the tampering test. |
| Input / output | `to_base64()` / `from_base64()` | Base64 encode/decode with readable errors for bad input. |
| | `show_line()` / `show_block()` / `show_package()` | Aligned, wrapped terminal output. |
| Menu actions | `action_generate_key()` | Option 1. |
| | `action_encrypt()` | Option 2; remembers the last message in `state`. |
| | `action_decrypt()` | Option 3; can reuse the last message. |
| | `action_test_wrong_key()` | Option 4. |
| | `action_test_tampering()` | Option 5. |
| | `main()` | Banner, menu loop, input validation, exit. |

### Important parameters

| Constant | Value | Meaning |
|----------|-------|---------|
| `KEY_SIZE` | 32 bytes | 256 bits → AES-256 |
| `NONCE_SIZE` | 12 bytes | 96 bits → the nonce size recommended for GCM |
| `TAG_SIZE` | 16 bytes | 128-bit authentication tag |

---

## The three security tests

### Test 1 — Correct key (option 3)

Bob decrypts with the same key Alice used. The tag verifies, decryption succeeds,
and the program confirms the plaintext matches the original.

### Test 2 — Incorrect key (option 4)

A completely new random 256-bit key is generated for Bob. Because GCM's tag is
derived from the key, the nonce and the ciphertext, verification fails and
`InvalidTag` is raised:

```text
  [PASS] Decryption failed with an authentication error (InvalidTag).
  [PASS] No plaintext was revealed to Bob.
```

The key fingerprints are printed so you can see the two keys really are different
without exposing either key.

### Test 3 — Ciphertext tampering (option 5)

An attacker flips the lowest bit of the first ciphertext byte. The nonce stays the
same, only one bit changes, yet authentication fails:

```text
  [PASS] Decryption failed with an authentication error (InvalidTag).
  [PASS] The tampering was detected and no plaintext was released.
```

This is the whole point of an authenticated cipher: **any** modification — a
changed byte, a truncated message, a substituted nonce — is detected.

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
text so they are easy to copy and paste. Base64 is **only** an encoding — it adds
no security whatsoever. It is reversible by anyone.

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
- **No replay protection.** An attacker who records a valid `(nonce, ciphertext)`
  pair cannot read or alter it, but can resend it later. Real protocols use
  counters, timestamps or sequence numbers.
- **No forward secrecy.** If the long-term key leaks, previously recorded traffic
  can be decrypted. Ephemeral key exchange prevents that.
- **Ciphertext length is visible.** Encryption hides the content, not the size or
  the timing of messages.
- **Terminal output is a teaching aid,** not a wire format. In a real system the
  nonce and ciphertext would be sent as bytes with a defined message layout.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'cryptography'` | Dependency not installed, or the virtual environment is not activated. | `pip install -r requirements.txt` |
| `[FAIL] No key file found. Use option 1 to create secret.key.` | `secret.key` is missing. | Run option **1**. |
| `[FAIL] Could not read the key file: key file must contain 32 bytes...` | The file was edited or truncated. | Run option **1** and overwrite it. |
| `[FAIL] Authentication failed: wrong key, or the nonce/ciphertext was modified.` | Wrong key, or the message was altered in transit. | Use the same `secret.key` on both sides; re-copy the Base64 exactly. |
| `[FAIL] Invalid input: nonce is not valid Base64` | Pasted text is truncated or contains extra characters. | Copy the whole value again (whitespace is ignored, other characters are not). |
| `SyntaxError` on Python 3.9 or older | The code uses `bytes | None`. | Use Python 3.10+ (or newer). |
| Empty `secret.key` / permission denied | A failed write, or file permissions. | Delete the file, then run option **1** again. |
| Different output every run | Expected: nonces are random. | Nothing to fix — this is correct behaviour. |

To regenerate the recording in `sample_output.txt`, delete `secret.key` and
`sample_output.txt` first, then run the same option sequence shown above.

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
