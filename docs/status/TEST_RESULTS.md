# CRYPTOGRAM Test Results

> **Scope clarification**: The tests referenced here are **static wiring checks** (file presence, symbol existence, grep-based verification). They do not constitute runtime, crypto, or device-level validation. See `docs/status/TEST_HARNESS_SCOPE.md` for the exact scope.

**Date**: 2026-04-20 (last reviewed)
**Harness**: `run_tests.sh` + `check_syntax.sh`
**Status**: Static harness passes; runtime/device validation pending

---

## Current Harness Summary

The `run_tests.sh` static harness verifies:
- JNI method name wiring (Double Ratchet, MLS, OPSEC)
- Kotlin ↔ native binding presence
- Message flow hook presence (outgoing/incoming)
- Settings toggle presence
- CMake build declarations
- Unit test target wiring

**Latest result**: 80/80 static checks pass, 0 warnings, 0 failures.

This confirms the documented CRYPTOGRAM surface is wired into source and test assets. It does **not** prove compilation, packaging, device runtime, or crypto correctness.

---

## What the Static Harness Validates

### JNI Wiring (TEST 2)
- Double Ratchet: `nativeInitializeSession`, `nativeEncrypt`, `nativeDecrypt`, `nativeGetState` — present
- MLS: `nativeCreateGroup`, `nativeEncryptGroupMessage`, `nativeDecryptGroupMessage`, `nativeAddMember`, `nativeRemoveMember` — present
- OPSEC: `nativeWrapDpiEvasion`, `nativeSecureWipe`, `nativeCheckPQC` — present
- Voice Morphing: `nativePitchShift`, `nativeFormantShift` — present
- Tor: `nativeTorStart`, `nativeTorStop`, `nativeTorStatus`, `nativeTorSocksProxy` — present

### Integration Hooks (TEST 3)
- Outgoing encryption hook in `SendMessagesHelper.java` — present
- Incoming decryption hook in `MessageObject.java` — present
- Settings entry point in `ProfileActivity.java` — present

### Build Declarations (TEST 4)
- `cryptogram` shared library declared in Android CMakeLists.txt — present
- Cryptogram linked into JNI target — present
- Feature unit test targets wired — present

### Runtime Gaps (TEST 5 — manual review)
- Some JNI wrapper paths still contain placeholder call paths
- Desktop MLS has been upgraded to real crypto (AES-256-GCM, X25519, Ed25519, HKDF)
- Android MLS still contains some placeholder crypto paths
- Desktop voice morphing now uses real DSP (WSOLA pitch shift, LPC formant shift)
- Android voice morphing JNI implemented with matching DSP algorithms
- Tor JNI bridge implemented with dlopen-based libtor loading and external proxy fallback

---

## What Is NOT Validated

- APK compilation and packaging (requires Android SDK/NDK on CI)
- Native library loading on device
- Encryption/decryption round-trip at runtime
- Key ratcheting correctness
- MLS group lifecycle (membership changes, transcript persistence)
- Cross-device messaging
- Performance or memory behavior
- Desktop Linux clean build (in progress — M1)

---

## Recommended Next Steps

1. **M1**: Complete Linux desktop clean build
2. **M2**: Validate Android APK builds from the `telegram-android` submodule
3. **M3**: Add runtime tests for JNI bridge behavior and message round-trips
4. Add device-level validation before any production readiness claim
5. Split test reporting into: static wiring, build, runtime, crypto, device tiers

---

## Test Harness Scope Reference

See `docs/status/TEST_HARNESS_SCOPE.md` for the definitive statement on what `run_tests.sh` does and does not cover.
