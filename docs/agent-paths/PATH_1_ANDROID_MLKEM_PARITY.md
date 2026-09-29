# AGENT PATH 1 — Android ML-KEM (post-quantum) parity

**Scope:** `telegram-android/TMessagesProj/jni/cryptogram/**`, `tests/unit/`
**Do NOT touch:** anything under `Telegram/SourceFiles/` (desktop is read-only
reference), `Telegram/lib_base`, any Java file outside
`telegram-android/.../cryptogram/`, `data_enhanced_privacy.*` (another agent's
in-flight work), `data_covert_channel.cpp` (Path 3).

## Objective

Android currently PARSES the desktop's post-quantum bundle extension (0x02 in
the key bundle bitmap) but does not emit a KEM key and does not wrap/unwrap
PQ envelopes. Desktop does both. Bring Android to full PQ parity:

1. Android generates and persists a static ML-KEM keypair (per account).
2. Android advertises its KEM public key in its own key bundle (bitmap 0x02).
3. When a session peer has advertised a KEM key, Android wraps outgoing 1:1
   message payloads in the desktop's PQE1 envelope and unwraps incoming ones.

## Verified background (trust this; do not re-derive)

Desktop side (READ-ONLY reference, `Telegram/SourceFiles/data/`):

- `data_signal_protocol.cpp` — `quantumWrapPayload` / `quantumUnwrapPayload` /
  `ensureQuantumIdentity` / `peerQuantumKeyPath` are the canonical PQ layer.
  Envelope format (built after the classic ratchet encrypts? NO — before:
  the PQ envelope wraps the PLAINTEXT, then the ratchet encrypts the whole
  thing; receiver order is ratchet-decrypt first, then PQ-unwrap):
  `"PQE1"` (4 bytes) | `u32be encapsulated-length` | encapsulated secret |
  `iv` (12) | `authTag` (16) | ciphertext.
- `data_quantumguard.cpp` — `quantumEncapsulate(keyId)` (real EVP_PKEY_
  encapsulate, ML-KEM), `quantumDecapsulate(keyId, encap)` (real decapsulate
  → same shared secret), `importPeerKemPublicKey` (SPKI DER, identifies keys
  via `EVP_PKEY_get0_type_name` — provider keys have NO legacy NIDs, so never
  use `EVP_PKEY_get_base_id` for ML-KEM), `importPeerKemPublicKeyRaw`
  (raw fixed-length encoding), `saveKeys`/`loadKeys` (AES-256-GCM +
  PBKDF2-SHA256 key file).
- Key advertisement: `data_signal_transport.cpp` `encodeKeyBundle` bitmap
  0x02 = `u16le len + SPKI DER`; parsed by Android's
  `DesktopBundleTransport.decodeKeyBundle` already (it returns
  `DecodedBundle.quantumKemPublicKey`, parse-only today).

Android side (YOUR files):

- `telegram-android/TMessagesProj/jni/cryptogram/interop/InteropCore.{h,cpp}` —
  JNI-free protocol core (host-compilable: NO jni.h, NO android/log.h, C++14 —
  `std::optional` is unavailable, use desktop convention: empty vector =
  failure). BoringSSL guard: hkdf mode setter is
  `EVP_PKEY_CTX_set_hkdf_mode` on OpenSSL but
  `EVP_PKEY_CTX_hkdf_mode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)` on BoringSSL —
  follow the existing backend-guard pattern in that file.
- `telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp` —
  per-user session map + JNI surface.
- `telegram-android/TMessagesProj/jni/CMakeLists.txt` — InteropCore.cpp is
  already listed; add any new .cpp there.
- `telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/
  cryptogram/DesktopBundleTransport.java` — already emits bitmap 0x05
  (0x01 OTP | 0x04 X25519 identity) and parses 0x02. Extend the EMIT to
  include 0x02 when the native bundle carries a KEM key (the native
  serializeKeyBundle path is in InteropCore, so this may require only
  native changes plus a Java passthrough — check `fromNativeBundle`).
- Persistence precedent: the DESKTOP persists its KEM identity via
  QuantumGuard::saveKeys to `<storage>/pq_identity.qgk` + a JSON meta file
  with keyId/publicDer. Mirror that shape on Android (see Path 2 for the
  storage location convention — coordinate: Path 2 owns
  `identifyStoragePath`; if Path 2 has not merged, define
  `interopStoragePath()` in InteropCore as `<filesDir>/cryptogram/interop/`
  via JNI-passed directory).

## Tasks

1. InteropCore: add `generateKemIdentity()` (EVP_PKEY_Q_keygen "ML-KEM-1024";
   export raw public + persist-capable private export), `importPeerKemRaw`,
   `kemEncapsulate(peerKeyRef)` → {sharedSecret(32), ciphertext}, and
   `kemDecapsulate(keyRef, ciphertext)` → sharedSecret. All pure
   C++/OpenSSL, host-compilable, no JNI types.
2. InteropCore: `wrapPqe1(peerKeyRef, plaintext)` and
   `unwrapPqe1(keyRef, blob)` implementing the PQE1 layout above with
   AES-256-GCM (shared secret is the AES-256 key directly, 12-byte IV,
   16-byte tag — mirror desktop exactly).
3. CryptogramWrapper: persist the KEM identity (choose file
   `<jni-passed-dir>/pq_identity`; implement save/load with PBKDF2 the same
   way QuantumGuard does — copy the parameter choices, not the code), emit
   the KEM public key (SPKI DER via i2d_PUBKEY) inside
   `generateLocalIdentity`/`localKeyBundle`, accept peer KEM keys, and call
   wrap/unwrap around the ratchet: wrap BEFORE ratchet-encrypt on send,
   unwrap AFTER ratchet-decrypt on receive, keyed by whether the peer's
   registered bundle carried 0x02. Gate: reuse the desktop's gate
   semantics — wrap only when the peer advertised a key.
4. DesktopBundleTransport.java: extend the emit path with 0x02 when present
   (parse already exists). No CryptogramMessageHelper changes should be
   needed (the framing is format-agnostic), but verify.
5. Keep ALL existing JNI signatures. Keep C++14. Keep the BoringSSL guard.

## Verification gates (all must pass; report outputs)

1. Host test (g++ -std=c++17, -lcrypto, no JNI): InteropCore-only roundtrip —
   Alice generates KEM identity, imports Bob's KEM public, wraps a payload,
   Bob decapsulates with his private half and unwraps to the identical
   plaintext; tamper → failure; wrong private key → different secret.
   Include an RFC-style known-answer check for the HKDF helper if you touch it.
2. SPKI DER roundtrip: i2d_PUBKEY/d2i_PUBKEY on the generated ML-KEM key.
3. NDK compile-only (BoringSSL include
   `telegram-android/TMessagesProj/jni/boringssl/include`, C++14) of
   InteropCore.cpp + CryptogramWrapper.cpp: zero errors.
4. `bash run_tests.sh` and `bash run_e2e_tests.sh` still PASS.

## Guardrails

- The PQE1 magic, field order, and sizes are FROZEN by the desktop — do not
  redesign the envelope. If you find a real defect in it, STOP and report.
- Do not enable PQ unconditionally: wrap ONLY when the peer advertised 0x02.
- Do not alter the classic ratchet derivation.

## Report back

Files changed, public API added, host-test output, NDK compile output,
harness outputs, deviations with reasons.
