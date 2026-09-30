# CAC/PIV Provisioning Runbook — FIPS YubiKey Test Hardware

Scope: this runbook brings a **FIPS YubiKey in PIV mode** up as test hardware
for the desktop CAC backend (`Telegram/SourceFiles/data/data_cac_interface.cpp`,
Linux PC/SC implementation) and its probe (`tests/unit/test_cac_piv_probe.cpp`).

A YubiKey is **not a DoD CAC** — it has no DoD-issued certificates. The goal is
to exercise the PC/SC + PIV code path end to end (reader discovery, card
presence, PIV applet select, 9a certificate read, hardware-backed RSA-2048
signing). DoD chain-of-trust validation is a separate concern — see
["What this proves vs what DoD-CAC adds"](#what-this-proves-vs-what-dod-cac-adds).

Host prerequisites (already true on t420 and in CI):

```bash
sudo apt install libpcsclite-dev pcscd   # PC/SC middleware + headers
systemctl status pcscd                    # must be active
ls /usr/include/PCSC/winscard.h           # headers present
```

## 1. Install the provisioning tools

```bash
sudo apt install yubico-piv-tool    # PIV provisioning CLI used below
# Optional alternative CLI:
sudo apt install yubikey-manager    # provides `ykman` (PIV status, resets)
yubico-piv-tool --version
lsusb | grep -i yubico              # confirm the device is attached
```

## 2. Check PIV status

```bash
yubico-piv-tool -a status
```

You should see the PIV version, a slot list (9a = PIV Authentication), and the
retry counters. If PIV is not initialized or the CCID interface is disabled:

```bash
ykman info                          # shows enabled USB interfaces
ykman config usb --enable CCID      # enable the CCID interface (re-plug after)
```

## 3. PINs and management key (factory defaults)

| Secret          | Default                                        |
|-----------------|------------------------------------------------|
| PIV PIN         | `123456`                                       |
| PIV PUK         | `12345678`                                     |
| Management key  | `010203040506070801020304050607080102030405060708` (48-byte hex, TDES/AES) |

For the test key keep the default PIN so the app-side flows (`verifyPIN`,
probe `CAC_PROBE_PIN=123456`) are predictable. Wrong-PIN behavior: each failed
VERIFY decrements the retry counter (SW `63 CX`); at 0 the PIN is blocked and
GENERAL AUTHENTICATE returns `69 83` (mapped to `CardLocked`).

```bash
# Optional: change the PIN away from the default (interactive)
yubico-piv-tool -a change-pin
# Verify the PIN (consumes nothing on success; restores the retry counter):
yubico-piv-tool -a verify-pin
```

## 4. Generate an RSA-2048 key in slot 9a (on-device)

The spike backend signs with PIV algorithm `0x07` (RSA 2048) against key
reference `9A`, so slot 9a must hold an RSA-2048 key. Generate it **on the
device** so the private key never leaves the YubiKey:

```bash
yubico-piv-tool -s 9a -A RSA2048 \
    --pin-policy=once --touch-policy=never \
    -a generate -o public9a.pem
```

Policy notes for the spike:

- `--pin-policy=once` — PIN is asked once per card session (the desktop app
  calls `verifyPIN` then signs; the probe sends `CAC_PROBE_PIN`).
- `--touch-policy=never` — no physical touch needed per signature. If you set
  `always` (or `cached`), signing BLOCKS until the user touches the YubiKey
  (the blinking LED); the PC/SC transmit has no client-side timeout and simply
  waits for the touch.

## 5. Create and import a self-signed test certificate

Slot 9a also needs the X.509 certificate — GET DATA (tag `5F C1 05`) reads it.
Self-signed with a clearly-marked test subject:

```bash
yubico-piv-tool -s 9a -a verify-pin \
    -a selfsign -A RSA2048 \
    -S "/CN=CRYPTOGRAM Spike (YubiKey PIV)/O=CRYPTOGRAM Test/C=US" \
    -d 3650 \
    -i public9a.pem -s cert9a.pem

yubico-piv-tool -s 9a -a import-certificate -i cert9a.pem
```

Verify what the backend will actually read:

```bash
yubico-piv-tool -s 9a -a read-certificate | openssl x509 -noout -subject -issuer -dates -serial
```

## 6. Run the probe

```bash
cmake -DCRYPTOGRAM_BUILD_TESTS=ON -B build_tests
cmake --build build_tests --target test_cac_piv_probe -j4

CAC_PROBE_PIN=123456 ./build_tests/tests/unit/test_cac_piv_probe
```

Expected output (order may vary):

```
[PASS] PC/SC readers found: 1
  - Yubico YubiKey OTP+FIDO+CCID 01 00
[PASS] Card present on "Yubico YubiKey OTP+FIDO+CCID 01 00" (ATR: 3B F8 02 1C 00 00 ...)
  connected to "..." (protocol T=1)
  PIV card application selected
[PASS] 9a certificate fetched (NNNN bytes DER)
  subject : /CN=CRYPTOGRAM Spike (YubiKey PIV)/O=CRYPTOGRAM Test/C=US
[PASS] signature produced (256 bytes)
[PASS] signature verifies against the 9a certificate
Probe: N check(s), 0 failure(s) — PASS
```

Without hardware the probe exits 0 after printing instructions ("plug in the
YubiKey and re-run"), so `run_tests.sh` stays green on machines without a key.

## 7. Reset PIV if the PIN/PUK is locked out

If PIN and PUK are both exhausted, reset the PIV application (wipes all slots
and restores default PIN/PUK/management key):

```bash
ykman piv reset            # prompts for confirmation
# or: yubico-piv-tool -a reset
```

Then repeat sections 4-5. (A YubiKey whose management key was changed and
forgotten must be factory-reset via `ykman piv reset` as well.)

## 8. What the backend does with this (APDU sequence)

`data_cac_interface.cpp` (Linux, `CRYPTOGRAM_HAS_PCSC`) implements:

| Step | APDU | Purpose |
|------|------|---------|
| Reader/card | `SCardEstablishContext`, `SCardListReaders`, `SCardGetStatusChange` (0 ms) | discovery, `isCardPresent` |
| Select PIV  | `00 A4 04 00 05 A0 00 00 03 08` (fallback: full 9-byte AID `A0 00 00 03 08 00 00 10 00`) | PIV applet select |
| Cert read   | `00 CB 3F FF 05 5C 03 5F C1 05 00` | GET DATA, X.509 Certificate for PIV Authentication (slot 9a) |
| PIN verify  | `00 20 00 80 08 <PIN padded to 8 bytes with 0xFF>` | `verifyPIN`; `00 20 00 80 00` (Lc=0) reads the retry counter for `getRemainingPINAttempts` |
| Sign        | `00 87 07 9A <Lc> 7C <L> 81 <L> <PKCS#1 v1.5 EM> [Le]` | GENERAL AUTHENTICATE, alg `0x07` = RSA 2048, key `9A`; the EM (`00 01 FF..FF 00 ‖ DigestInfo(SHA-256) ‖ digest`) is built host-side, the card applies the private-key op; response `7C <L> 82 <L> <signature>` |

Extended APDUs (3-byte Lc, RSA-2048 GA body is 264 bytes) are used when the
card negotiated T=1 — the YubiKey CCID interface always does.

<a name="what-this-proves-vs-what-dod-cac-adds"></a>
## 9. What this proves vs what DoD-CAC adds

**Proven by the YubiKey spike:**

- PC/SC transport works end to end on Linux (pcscd + libpcsclite, T=1).
- PIV applet select, object fetch (`GET DATA`), certificate parse (DER/X.509).
- Hardware-backed RSA-2048 PKCS#1 v1.5 / SHA-256 signing through
  `GENERAL AUTHENTICATE`, PIN-gated per the slot policy.
- The consumer path in `data_signal_protocol.cpp` (`CACFactory::create()` →
  `isCardPresent()` → `getCardInfo()` → `signData()`) runs against real
  hardware instead of returning `CardNotFound`.

**NOT proven by the spike — what full DoD-CAC support adds:**

- **Chain of trust**: real CAC certificates chain to DoD/NATO roots. The app
  validates this in `SignalProtocol::verifyCacMutualAuth()` against
  `<appDir>/keys/nato`; that path stays gated on real DoD root certificates
  and is not exercised by a self-signed YubiKey cert (and must not be bypassed).
- **DN semantics**: DoD DNs (`CN=DOE.JOHN.A.1234567890,OU=CONTRACTOR,...`) and
  EDIPI-based green-name identification, versus the spike's test CN.
- **Card edge cases**: multi-applet CACs, CHUID/FASC-N based card serials,
  reader PIN pads, secure messaging, and card-mgmt flows that only appear on
  actual issued CACs.

Consequence: after the spike, CAC code is *hardware-testable*; declaring DoD
*interop* still requires real CAC certificates and a `keys/nato` trust store.
