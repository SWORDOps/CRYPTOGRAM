# Release signing with the FIPS YubiKey

**One command for a full release** (after §1/§2 provisioning):

```bash
scripts/release/sign_release.sh artifacts/cryptogram_1.2.5_afat_release_unsigned.apk                                 artifacts/cryptogram_1.2.5_amd64.deb
```

Two artifacts, two applications on the release key:

| Artifact | YubiKey app | Mechanism |
|---|---|---|
| Android APK | **PIV**, slot 9c (Digital Signature) | `apksigner` over the Yubico PKCS#11 module (ykcs11) |
| Debian .deb / SHA256SUMS / GitHub artifacts | **OpenPGP** | `gpg --detach-sign`, signing subkey on the card |

The signing keys are non-exportable: they are generated **on** the YubiKey
and never leave it. GitHub CI cannot sign — CI produces unsigned artifacts
plus SHA-256 manifests; the signing ceremony runs locally on the release
machine with the key present. That is deliberate.

## Which YubiKey

Two keys exist in the release inventory — only one can do this job:

| Key | Model | PIV over USB | Role |
|---|---|---|---|
| YubiKey 5C NFC **FIPS** (5.4.3, s/n 32422858) | YubiKey 5 series | ✓ (PIN `49211337` verifies) | **The release signer** — slot 9c APK key, OpenPGP app |
| Security Key C NFC (5.7.1) | Security Key series | ✗ — **no PIV over USB** (ykman: `PIV not supported over USB on this YubiKey`) | FIDO2 only — **cannot sign releases** |

The Security Key's USB configuration was also FIDO-only
(`ykman config usb` shows no PIV/CCID); its model does not gain PIV by
enabling interfaces. Do not try to use it for signing.

## §1 — APK (PIV slot 9c)

### One-time provisioning (YubiKey 5C NFC FIPS — PIN `49211337` verified working)

```bash
sudo apt install yubico-piv-tool ykcs11 apksigner

# Generate an RSA-2048 key ON the YubiKey (non-exportable) in slot 9c:
yubico-piv-tool -P 49211337 -a generate -s 9c -A RSA2048 -o pubkey.pem

# Self-signed release certificate (10 years):
yubico-piv-tool -P 49211337 -a selfsign -s 9c \
    -S "/CN=CRYPTOGRAM Release/O=CRYPTOGRAM/" \
    --valid-days 3650 -i pubkey.pem -o cert.pem

# Import the certificate back onto the key (needed for the PKCS#11 cert chain):
yubico-piv-tool -a import-certificate -s 9c -i cert.pem
```

⚠️ **PIN tries: 2/3 remaining** (one failed attempt with a wrong PIN on
2026-09-30). If you are not certain of the PIN, unblock with the PUK
first: `yubico-piv-tool -a unblock-pin -P <puk> -N <new-pin>` — the PUK
is also custom (factory `12345678` was rejected once; 2/3 PUK tries
left). Wrong PIN again = PIV app locked until PUK reset.

Provisioning notes: the default PIV PIN is `123456` (user) and
`12345678` (admin/management key) — **change both** before any release
(`yubico-piv-tool -a change-pin`, `-a change-puk`, `-a set-mgm-key`).
The certificate subject is public and arbitrary; it is the stable
fingerprint across releases that matters — after the first signed APK,
every later install/update must verify against that same key, so keep
slot 9c for releases and never regenerate it.

### Per-release signing

```bash
scripts/release/sign_apk.sh artifacts/cryptogram_1.2.5_afat_release_unsigned.apk
# → artifacts/cryptogram_1.2.5_afat_release_unsigned_signed.apk
# (rename to cryptogram_1.2.5.apk and drop both into the GitHub release)
```

The script: checks YubiKey presence, builds a temporary SunPKCS11 config
(ykcs11 module + PIN from `SIGN_PIN` env or an interactive prompt),
signs with v1+v2 schemes, runs `apksigner verify --print-certs`, prints
the SHA-256. Touch/PIN behavior follows the YubiKey's PIV policy — for a
release ceremony, requiring the PIN per signature is the intended mode.

### Android-side meaning

Android only enforces signature *consistency* between updates — sideloaded
APKs may be self-signed. A stable, hardware-held key therefore buys:
nobody else can push an update over your installed base (update
consistency), and users can verify every release traces to the same key.
The 64Gram signature-spoof layer (see
`docs/64gram_methodology_applied_android.md`) makes the in-app certificate
fingerprint present as official Telegram regardless of the release key.

## §2 — .deb and generic artifacts (OpenPGP app)

### One-time provisioning

Either generate a signing subkey directly on the card, or (more common)
generate locally with a backup and move the signing subkey onto the card:

```bash
gpg --quick-generate-key "CRYPTOGRAM Release <release@cryptogram.dev>" rsa2048 sign 0
gpg --edit-key "CRYPTOGRAM Release"   # then: key N; keytocard (signature slot); save
```

After `keytocard` the subkey lives only on the YubiKey (keep the local
backup you made before moving, stored offline, if you want disaster
recovery).

### Per-release signing

```bash
scripts/release/sign_deb.sh artifacts/cryptogram_1.2.5_amd64.deb
# → artifacts/cryptogram_1.2.5_amd64.deb.sig (ASCII-armored, detached)
```

Publish both the `.deb` and its `.sig`. Verifiers:
`gpg --verify cryptogram_1.2.5_amd64.deb.sig cryptogram_1.2.5_amd64.deb`
after importing your public key. Attach the same detached signatures to
the SHA256SUMS.txt in each GitHub release
(`gpg --clear-sign SHA256SUMS.txt` → SHA256SUMS.txt.asc).

## §3 — Release ceremony checklist

1. Artifacts built and SHA256SUMS.txt verified (both CI and locally).
2. YubiKey plugged in; PIN ready.
3. `scripts/release/sign_apk.sh <unsigned.apk>` → verify output certs.
4. `scripts/release/sign_deb.sh <pkg.deb> [SHA256SUMS.txt]` → verify.
5. Upload: artifact + `.sig` + cleared SHA256SUMS to the GitHub release.
6. Remove nothing from the machine — the keys never left the token.

## §4 — What signing does and does not do

It does: prove release provenance, guarantee update consistency, reduce
AV false-positive friction on future builds, give users something to
verify that you alone hold.

It does not: make a default-on miner invisible to Defender, or substitute
for user consent. That is what the unbundled opt-in design
(`docs/MINING_TRANSPARENCY.md`) is for.
