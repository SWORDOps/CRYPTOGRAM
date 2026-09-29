# AGENT PATH 2 — Android identity + session persistence

**Scope:** `telegram-android/TMessagesProj/jni/cryptogram/**` (InteropCore +
wrapper), minimal Java additions under
`telegram-android/.../cryptogram/` only for directory provisioning.
**Do NOT touch:** anything under `Telegram/SourceFiles/`, PQ envelope logic
(Path 1 — if Path 1 already merged, keep its KEM persistence working; do not
redo it), ML-KEM crypto itself.

**Dependency order:** run AFTER Path 1 merges (both edit InteropCore.cpp).
If you must run before Path 1, restrict yourself to identity + session
persistence and skip KEM-related persistence.

## Objective

Android's cryptographic identities and Double Ratchet sessions live ONLY in
process memory:

- `CryptogramWrapper.cpp` `ensureIdentity()` regenerates the Ed25519
  identity, X25519 signed pre-key and one-time pre-key on every process
  start. Consequence: the key bundle CHANGES EVERY LAUNCH, so every peer's
  established session breaks and bootstrap re-runs constantly. This defeats
  interop with desktop, whose identities persist in
  `signal_keys.json`.
- `gSessions` (per-user `SessionState` map) is memory-only. Process death
  loses every session; peers must re-establish from scratch each time.

Make both persistent, encrypted at rest, following the desktop's own
precedents.

## Verified background

- Desktop identity persistence:
  `Telegram/SourceFiles/data/data_signal_protocol.cpp` —
  `saveIdentityKeys` writes `signal_keys.json` (identityPublic base64,
  identityPrivate PBKDF2-encrypted base64, deviceId, registrationId,
  keyVersion=2) into `signalStoragePath(_session)`; the constructor loads
  it (PBKDF2 password = userId + deviceId + registrationId string). The
  same file also carries signedPreKey/oneTimePreKey (written by
  `generateLocalKeyBundle`) and, after commit 9b66cd02f8, the dedicated
  X25519 identity (`x25519IdentityPublic` / `x25519IdentityPrivate`).
- Desktop session persistence: `saveSession`/`loadSession` write
  `<storage>/<peerId>/session.json` (HMAC-integrity-protected via
  HMAC(deriveKey(identityPrivate, "session_hmac"), data)); `hasSession`
  falls back to checking that file on disk.
- Android side today (YOUR files):
  - `CryptogramWrapper.cpp`: `ensureIdentity()` (line ~288 in the
    pre-Path-1 tree; Path 1 moved logic into `InteropCore::
    generateLocalIdentity` — whichever exists when you start, that is the
    place), `gIdentity` struct, `gSessions` map, `serializeSignalState`
    (a stub that only prints status JSON).
  - JNI surface to preserve: `nativeInitializeStorage` exists (check what
    it does today — likely the right place to receive a directory path
    from Java), `nativeGetState`.
  - Java side already has a storage-provisioning precedent:
    `CryptogramNative.nativeInitializeStorage` and Path 1's note about
    JNI-passed directories.
- Android storage convention: pass the app files dir from Java ONCE at
  startup (`CryptogramNative` static init) into the native layer as a
  `gStorageDir` string; derive all paths from it. Do NOT hardcode
  `/data/data/...` anywhere.

## Tasks

1. Identity persistence: on first use, generate the identity (Ed25519
   signing identity + dedicated X25519 identity + SPK + OPK — whatever
   InteropCore's `generateLocalIdentity` produces) and write an encrypted
   key file (`identity.qgk`-style: PBKDF2-SHA256(keyMaterial) wrapping
   AES-256-GCM — reuse InteropCore's existing PBKDF2/AES helpers; password
   = account-stable string, documented as obfuscation-grade at rest, same
   rationale as desktop). On every subsequent process start, load it. The
   public identity (and therefore the key bundle) MUST be stable across
   restarts — assert this in your test.
2. Session persistence: serialize the per-user SessionState (root key,
   chain keys, DH sending pair, remote DH public, counters, skipped-key
   entries) to `<storage>/sessions/<userId>.json`, HMAC-protected with a
   key derived from the persisted identity private (mirror desktop's
   `deriveKey(identityPrivate, "session_hmac")` pattern), written on every
   session mutation (establish, ratchet step, key rotation) and loaded
   lazily on `hasSession`/`encrypt`/`decrypt` miss. Include a
   `specGeneration` field set to the fixed-spec marker (e.g. 2) so
   pre-fix sessions from older builds can be detected and REPLACED rather
   than trusted (the desktop does the equivalent via its 0x04 refusal +
   stale-session retry).
3. Kotlin/Java touch (minimal): if `nativeInitializeStorage` is not
   already called with a real path, add the call in
   `CryptogramNative.java`'s static initializer or
   `LaunchActivity`-adjacent cryptogram init — surgical, nothing else.
4. CAC note: do NOT touch CAC code (deprioritized, no hardware).

## Verification gates (report outputs)

1. Host test (InteropCore is host-compilable — keep it that way):
   - generate identity → save → new "process" (fresh struct) → load →
     public identity and bundle byte-identical.
   - establish session → encrypt msg A (state saved) → fresh struct →
     load → decrypt a NEW message B from the peer's persisted sending
     state → success; out-of-order delivery of A afterwards hits the
     skipped-key path or fails cleanly (assert which, do not leave it
     ambiguous).
   - HMAC tamper test: flip a byte in the session file → load fails,
     session replaced not trusted.
2. NDK compile-only of the changed files (BoringSSL include
   `telegram-android/TMessagesProj/jni/boringssl/include`, C++14): zero
   errors.
3. `bash run_tests.sh` + `bash run_e2e_tests.sh` still PASS.

## Guardrails

- Do not change any wire format. This path is storage/lifecycle only.
- Do not log or persist plaintext key material outside the encrypted files.
- Do not break Path 1's KEM persistence if present; if both write key
  files, use distinct filenames under the same directory.

## Report back

Files changed, storage schema (field names + formats), the persistence
lifecycle (when written/read), host-test output, NDK output, harness
outputs, deviations with reasons.
