# CRYPTOGRAM Issue Roadmap

Comprehensive audit of all known issues across Android, Desktop, Build System, and CI.
Last updated: 2026-08-09

---

## P0 — CI / Build Pipeline (Blocking Everything)

### CI-1: macOS disk space vs Xcode conflict
**Status:** Fix in progress (commit `6311b80`)
**Problem:** Qt's CMake requires `xcodebuild -version` (needs full Xcode), but Xcode takes ~41GB leaving insufficient space for the Qt build (~38GB needed).
**Current approach:** Remove iOS/watchOS/tvOS/XRiOS platform directories from within Xcode (~20-30GB) while keeping `xcodebuild` functional.
**Previous failed approaches:**
- Delete Xcode entirely → Qt CMake fails: "Can't determine Xcode version"
- Build breakpad first, then delete Xcode → breakpad needs `patches/breakpad.diff` which doesn't exist
**Verification:** macOS run `31310503044` currently in prepare.py (44m in, past previous 21m failure point).

### CI-2: macOS breakpad/stackwalk stages broken
**Status:** Fixed (commit `7d4a667`)
**Problem:** `prepare.py` breakpad and stackwalk stages require `xcodebuild` + `patches/breakpad.diff`. The patch file has never existed in this repo or upstream.
**Fix:** Added `SKIP_STAGES` env var to `prepare.py`; macOS CI sets `SKIP_STAGES="breakpad stackwalk"`.
**Impact:** Crash reporting (breakpad) is not built on macOS. Acceptable for CI build verification.

### CI-3: Windows zlib library name mismatch
**Status:** Fixed (commit in `cmake_helpers` fork)
**Problem:** `cmake/external/qt/package.cmake` referenced `zlibstatic.lib`/`zlibstaticd.lib` but the zlib build produces `libzs.lib`/`libzsd.lib`.
**Fix:** Updated `cmake/external/qt/package.cmake` in `SWORDOps/cmake_helpers` fork. Submodule pointer updated.
**Verification:** Previous Windows run confirmed zlib found: `-- Found ZLIB: optimized;...libzs.lib;debug;...libzsd.lib`.

### CI-4: Windows libsignal MSVC C compilation error
**Status:** Fixed (commit `15f112a`)
**Problem:** `libsignal/src/curve25519/ed25519/tests/internal_fast_tests.c` uses `const int MSG_LEN = 200` as array size. MSVC's C compiler rejects this (not a constant expression in C89/C90).
**Fix:** Forked `signalapp/libsignal-protocol-c` to `SWORDOps/libsignal-protocol-c`, replaced with `enum { MSG_LEN = 200 }`.
**Verification:** Pending — current Windows run in prepare.py, will reach Build Telegram in ~1.5h.

### CI-5: Linux .deb "Illegal instruction" in tde2e build
**Status:** Unfixed (transient/runner-dependent)
**Problem:** `cmake --build . --config Release --parallel 4` for tde2e fails with `Illegal instruction (core dumped)` in `tl_generate_tlo`. This is a CPU instruction compatibility issue with clang on certain GitHub runner hardware.
**Root cause:** The generated binary uses CPU instructions not supported by the runner's CPU.
**Possible fixes:**
- Add `-march=x86-64` or `-mno-avx` to CMake flags for tde2e build
- Retry on different runner (transient — sometimes works)
- Pin to a specific runner architecture
**Note:** Linux AppImage build (same code, different workflow) has not hit this issue.

### CI-6: Android APK artifacts not uploaded
**Status:** Fixed (pending push)
**Problem:** `build.gradle` hardcodes `outputFileName = "app.apk"`. The collect step searches for `*debug*.apk` / `*release*.apk` patterns that never match, so `debug_apk` and `release_apk` outputs are empty. Upload steps have `if: steps.collect.outputs.release_apk != ''` conditions that skip.
**Fix:** Rewrote collect step to detect build type from output path and rename to `cryptogram-{debug,release}.apk`. Applied to both `android-apk.yml` and `release.yml`.
**Verification:** Pending — next Android CI run will test the fix.

### CI-7: Tests never run in CI
**Status:** Unfixed
**Problem:** `CRYPTOGRAM_BUILD_TESTS` CMake option is OFF by default. No CI workflow enables it. 9 Catch2 test targets exist but are never compiled or executed.
**Fix needed:** Add a CI job (or step in existing Linux job) that passes `-DCRYPTOGRAM_BUILD_TESTS=ON` to cmake and runs the tests.

---

## P1 — Android: Encryption Not Wired In (App Ships Non-Functional) — ✅ DONE

### AND-1: Outgoing message encryption is an empty stub
**File:** `telegram-android/.../SendMessagesHelper.java:11893`
**Code:** `public void encryptOutgoingMessage() {}`
**Impact:** No outgoing message is ever encrypted. The native crypto library (`libcryptogram.so`) builds and loads, the Java wrapper (`CryptogramMessageHelper.encryptOutgoingMessage()`) is fully implemented, but the call site is empty.
**Fix:** Wire `SendMessagesHelper.encryptOutgoingMessage()` to call `CryptogramMessageHelper.encryptOutgoingMessage(accountInstance, message, peerId)` in the message send path. Need to find the actual send point in `SendMessagesHelper` and intercept the message text before it goes to MTProto.

### AND-2: Incoming message decryption is an empty stub
**File:** `telegram-android/.../MessageObject.java:13447`
**Code:** `public void decryptIncomingMessage() {}`
**Impact:** No incoming encrypted message is ever decrypted. Messages with CRYPTOGRAM markers (🔐, 🔐📦, 🔐🧩) are displayed as-is.
**Fix:** Wire `MessageObject.decryptIncomingMessage()` to call `CryptogramMessageHelper.decryptIncomingMessage(accountInstance, message, peerId, fromId)` when constructing message display text.

### AND-3: CRYPTOGRAM settings UI is an empty stub
**File:** `telegram-android/.../ProfileActivity.java:16829`
**Code:** `private void openCryptogramSettings() {}`
**Impact:** Users cannot enable/disable CRYPTOGRAM features. `SharedConfig` has 13 boolean flags (`cryptogramDoubleRatchet`, `cryptogramMLS`, etc.) with toggle methods, but no UI exposes them.
**Fix:** Create a `CryptogramSettingsActivity` or add a section to existing privacy settings. Add string resources and layout XML. Wire `openCryptogramSettings()` to launch the new activity.

### AND-4: No AndroidManifest entries for CRYPTOGRAM
**File:** `telegram-android/.../AndroidManifest.xml`
**Impact:** No CRYPTOGRAM-specific activities or permissions declared. If a settings activity is added, it must be registered here.
**Fix:** Add activity declarations when AND-3 is implemented.

### AND-5: No string resources or layouts for CRYPTOGRAM UI
**Files:** `res/values/strings.xml`, `res/layout/`
**Impact:** No user-facing text or UI layouts for CRYPTOGRAM features exist.
**Fix:** Add string resources and layout XML as part of AND-3.

### AND-6: Desktop C++ headers in Android JNI may not compile
**Files:** `telegram-android/TMessagesProj/jni/cryptogram/data/data_enhanced_privacy.h`, `data_signal_protocol.h`, `data_mls_protocol.h`
**Problem:** These headers reference Telegram Desktop / SpyGram Desktop includes and may not be Android-specific. The standalone `CryptogramWrapper.cpp` appears functional but includes these headers.
**Fix:** Verify these headers are actually used by `CryptogramWrapper.cpp` compilation. If not, remove them. If yes, adapt them for Android.

---

## P2 — Desktop: Incoming Decryption Not Wired In — ✅ DESK-1/2/3/4 DONE

### DESK-1: SignalProtocol::processIncomingMessage() is never called
**File:** `Telegram/SourceFiles/data/data_signal_protocol.cpp:2857`
**Problem:** The function is fully implemented (decrypts Double Ratchet messages) but has zero callers. Incoming encrypted 1:1 messages are never decrypted.
**Impact:** Outgoing encryption works (apiwrap.cpp:4255 calls `processOutgoingMessage`), but the recipient can't decrypt. Both sides must be wired for the protocol to function.
**Fix:** Call `processIncomingMessage()` in `history_item.cpp` where incoming messages are constructed (around line 545 where key bundle extraction already happens).

### DESK-2: GroupEncryption::decryptGroupMessage() is never called
**File:** `Telegram/SourceFiles/data/data_group_encryption.cpp:179`
**Problem:** Function is implemented but has zero callers. Incoming MLS-encrypted group messages are never decrypted.
**Fix:** Call `decryptGroupMessage()` in the message receive path when MLS ciphertext entities are detected (the `tg://cryptogram?part=...` custom URL entities that apiwrap.cpp creates on send).

### DESK-3: EnhancedPrivacy::EncryptString/DecryptString have commented-out OpenSSL
**File:** `Telegram/SourceFiles/data/data_enhanced_privacy.cpp:364-433`
**Problem:** Both functions generate key/IV but the actual `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex` calls are commented out. Functions return plaintext.
**Impact:** String encryption (used by covert channel and potentially settings) is non-functional.
**Fix:** Uncomment and complete the OpenSSL encryption/decryption implementation.

### DESK-4: CovertChannel encryption/decryption is disabled
**File:** `Telegram/SourceFiles/data/data_covert_channel.cpp:371-404`
**Problem:** `encryptForCovert()` and `decryptFromCovert()` return plaintext. Comments say `EnhancedPrivacy::GetEncryptionPassphrase()` is not implemented.
**Fix:** Implement `GetEncryptionPassphrase()`, then enable the encryption/decryption calls. Or wire to DESK-3 once fixed.

### DESK-5: Phase5NetworkSecurity MTP integration is incomplete
**File:** `Telegram/SourceFiles/data/data_phase5_network_complete.cpp`
**Problem:** `NetworkSecuredMTPConnection` is an empty class. `secureOutgoingMTPData()` and `processIncomingMTPData()` return original data. Setup functions are commented out. Signal emissions are commented out.
**Impact:** Network-level MTP data security is non-functional.
**Fix:** Either complete the implementation or remove the dead code. This appears to be an unfinished feature.

### DESK-6: TSM (Hardware Security) integration is stubs
**File:** `Telegram/SourceFiles/data/data_tsm_interface.cpp:415-422`
**Problem:** All methods return defaults: `initializeWithSignalProtocol()` returns Success without doing anything, `isHardwareBackedSecurity()` returns false, `generateSignalIdentityKeyPair()` returns error, `getTSMCapabilities()` returns empty.
**Impact:** Hardware-backed key storage is not available. Keys are stored in software.
**Fix:** Either implement TSM integration for target platforms or remove the stubs and document that hardware security is not supported.

### DESK-7: GroupEncryption channel/supergroup member detection not implemented
**File:** `Telegram/SourceFiles/data/data_group_encryption.cpp:257`
**Code:** `LOG(("GroupEncryption: Channel/supergroup member detection not yet implemented"));`
**Problem:** `getCryptogramMembers()` returns empty vector for channels/supergroups.
**Impact:** MLS group encryption only works for basic groups, not channels or supergroups.
**Fix:** Implement member detection using the Telegram API (`channels.getParticipants` or cached member data).

### DESK-8: TagLib audio metadata spoofing is disabled
**File:** `Telegram/SourceFiles/data/data_enhanced_privacy.cpp:50-62, 785`
**Problem:** All TagLib includes are commented out. `SpoofMediaMetadata` for audio files is a no-op.
**Impact:** Audio file metadata (artist, title, etc.) is not stripped/spoofed for privacy.
**Fix:** Enable TagLib integration or remove the dead code path. Image metadata spoofing (JPEG) works fine via the 3 call sites in `localimageloader.cpp`, `file_upload.cpp`, `api_peer_photo.cpp`.

### DESK-9: MLS welcome processing uses placeholder tree
**File:** `Telegram/SourceFiles/data/data_mls_protocol.cpp:1037-1038`
**Code:** `// Initialize with a placeholder tree (real implementation would decrypt the encrypted group secrets and group info from the welcome)`
**Impact:** MLS group join via welcome message may not work correctly.
**Fix:** Implement proper welcome message decryption and tree initialization.

---

## P3 — Build System Issues

### BUILD-1: build_all.sh silently skips failed dependencies
**File:** `build_all.sh` (lines 444-856, 11 instances)
**Problem:** 11 dependency build functions silently `return 0` on failure, allowing the build to continue without critical components (tg_owt, tde2e, OpenAL, LZ4, xxHash, minizip, rlottie, RNNoise).
**Impact:** Build may succeed but produce a non-functional binary missing WebRTC, E2E, audio, or compression support.
**Fix:** Add a `--strict` mode that fails on dependency errors, or at minimum log a prominent warning and track skipped deps in a summary at the end.

### BUILD-2: tde2e build has no CPU instruction handling
**File:** `build_all.sh:831-873`
**Problem:** No detection or workaround for "Illegal instruction" errors on incompatible CPUs (see CI-5).
**Fix:** Add `-march=x86-64` or detect CPU features before building. Consider `-DCMAKE_C_FLAGS="-mno-avx -mno-avx2"` for the tde2e build.

### BUILD-3: Four data files excluded from CMake build
**File:** `Telegram/CMakeLists.txt`
**Excluded:**
- `data/data_birthday.cpp` — duplicate symbol error
- `data/data_messages.cpp` — no reason given
- `data/data_network_mesh.cpp` — missing QtWebSockets dependency
- `data/data_statistics_chart.cpp` — duplicate symbol error
**Fix:** Resolve the duplicate symbol errors (likely ODR violations from inline definitions in headers). Add QtWebSockets dependency for network_mesh.

### BUILD-4: Missing CRYPTOGRAM_changelog.txt
**File:** `Telegram/CMakeLists.txt:2505` references `CRYPTOGRAM_changelog.txt`
**Problem:** File does not exist in the repository.
**Fix:** Create the file or remove the reference from CMakeLists.txt.

### BUILD-5: Submodule fork sync risk
**File:** `.gitmodules`
**Problem:** 2 SWORDOps forks (`cmake_helpers`, `libsignal-protocol-c`) and 4 TDesktop-x64 forks may diverge from upstream without notice.
**Fix:** Set up automated upstream sync (GitHub Actions or Dependabot for submodules). Document fork purposes in `.gitmodules` or a README.

---

## P4 — Testing Gaps

### TEST-1: Unit tests exist but are never run
**Files:** `tests/unit/` (9 test files, 9 Catch2 targets)
**Problem:** `CRYPTOGRAM_BUILD_TESTS=OFF` by default. No CI workflow enables it.
**Fix:** Add a CI job that builds with `-DCRYPTOGRAM_BUILD_TESTS=ON` and runs the test suite. Run on every PR.

### TEST-2: run_tests.sh is static-only
**File:** `run_tests.sh`
**Problem:** Only checks file existence and pattern matching. Does not compile or execute tests.
**Fix:** Either upgrade to run actual Catch2 tests, or rename to `verify_files.sh` to avoid confusion.

### TEST-3: No integration tests for message encryption roundtrip
**Problem:** No test verifies that a message encrypted on one platform can be decrypted on another (or even the same platform).
**Fix:** Add an E2E test that encrypts a message via `SignalProtocol::processOutgoingMessage()` and decrypts via `processIncomingMessage()`.

### TEST-4: No Android instrumentation tests
**Problem:** No tests verify that `CryptogramMessageHelper` correctly intercepts and encrypts/decrypts messages in the Android app.
**Fix:** Add instrumented tests that exercise the JNI bridge and message helper.

---

## Summary by Priority

| Priority | Category | Count | Status |
|----------|----------|-------|--------|
| P0 | CI/Build Pipeline | 7 | 4 fixed, 1 in progress, 2 unfixed |
| P1 | Android Integration | 6 | 0 fixed — all stubs |
| P2 | Desktop Integration | 9 | 0 fixed — incoming decryption + several stubs |
| P3 | Build System | 5 | 0 fixed |
| P4 | Testing | 4 | 0 fixed |
| **Total** | | **31** | **4 fixed, 1 in progress, 26 unfixed** |

## Recommended Execution Order

1. **Finish P0** — Get all 4 platforms building in CI (macOS and Windows pending verification)
2. **P1 Android wiring** — Make the APK actually encrypt messages (AND-1, AND-2, AND-3)
3. **P2 Desktop incoming** — Wire `processIncomingMessage()` and `decryptGroupMessage()` (DESK-1, DESK-2)
4. **P2 Desktop crypto** — Fix the commented-out OpenSSL in EnhancedPrivacy (DESK-3, DESK-4)
5. **P4 Testing** — Enable unit tests in CI (TEST-1), add roundtrip test (TEST-3)
6. **P3 Build hardening** — Strict mode for build_all.sh (BUILD-1), fix tde2e CPU issue (BUILD-2)
7. **P2 Remaining** — Phase5, TSM, supergroup members, TagLib, MLS welcome (DESK-5 through DESK-9)
8. **P3 Remaining** — Excluded files, missing changelog, fork sync (BUILD-3, BUILD-4, BUILD-5)
