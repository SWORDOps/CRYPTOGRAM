# CRYPTOGRAM Audit Gaps

Audit date: 2026-04-03
Repo root: `/media/john/NVME_STORAGE10/CRYPTOGRAM`
Branch: `dev`

## Scope

This audit compares the current repository state against the active documentation and status claims in:

- `README.md`
- `docs/README.md`
- `docs/features/android-features.md`
- `docs/features/desktop-features.md`
- `docs/status/FINAL_STATUS.md`
- `docs/status/TEST_RESULTS.md`
- `docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md`
- `docs/dev/PULL_REQUEST.md`
- `QUICK_START.md`

It focuses on whether documented features are:

- backed by implementation,
- actually wired into builds,
- covered by meaningful tests,
- accurately described by the current docs.

## Executive Summary

The repository contains substantial CRYPTOGRAM work in both the Android and desktop trees, but the documentation is not yet consistently truthful about what is implemented, what is only present in-source, and what is actually verified.

Highest-risk mismatches:

1. Status and implementation docs still describe Android as effectively complete and deployment-ready, while the shipped verification harness is explicitly static-only and there are no in-tree Android runtime tests.
2. Desktop CRYPTOGRAM settings advertise features that are explicitly disabled, stubbed, or marked not implemented in code.
3. Desktop build configuration still comments out several data-layer CRYPTOGRAM modules that the docs describe as present features.
4. Android crypto docs need tighter wording: the wrapper now contains real AES-GCM session handling and MLS plumbing, but some crypto paths still rely on placeholder logic and should not be presented as fully audited end-to-end behavior.
5. Some documentation indexes and development notes still point to stale paths or outdated status language.

## Findings

### P0: Test and readiness docs materially overstate what has been verified

The current status docs still frame the Android work as effectively build-ready and fully verified:

- `docs/status/TEST_RESULTS.md`
- `docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md`
- `docs/dev/PULL_REQUEST.md`

But the actual verification harness says otherwise:

- `run_tests.sh`
- `docs/status/TEST_HARNESS_SCOPE.md`

Observed behavior:

- `run_tests.sh` checks file existence, symbol presence, wiring, and selected grep-based patterns.
- `docs/status/TEST_HARNESS_SCOPE.md` explicitly says the script does not compile the app, run on a device, prove encryption correctness, or validate UI/runtime behavior.
- There are no Android `test/` or `androidTest/` directories under `TMessagesProj/src`.

Impact:

- Claims such as "ALL TESTS PASSED", "READY FOR BUILD & DEPLOYMENT", and "production-quality implementation" are stronger than the repository can currently prove.
- Documentation should distinguish static source verification from build/runtime/crypto validation.

### P0: Desktop settings surface is out of sync with actual implementation status

The desktop settings UI presents several CRYPTOGRAM features as active user-facing capabilities:

- `Telegram/SourceFiles/settings/settings_cryptogram.cpp`

But the same file explicitly marks core parts as disabled or not implemented:

- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:554`
- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:560`
- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:620`
- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:655`
- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:704`
- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:844`
- `Telegram/SourceFiles/settings/settings_cryptogram.cpp:850`

Examples:

- Double Ratchet enablement is hardcoded disabled because `EnhancedPrivacy` integration is still marked not implemented.
- Group encryption status is shown as "Not initialized" with a `Data::GetGroupEncryption()` TODO.
- Covert channel messaging is explicitly marked not implemented.
- Device Trust is explicitly marked not fully implemented.

Impact:

- Desktop-facing docs and desktop UI copy currently oversell feature readiness.
- This is a direct blocker for claiming the desktop product is complete versus documentation.

### P0: Desktop build configuration still excludes CRYPTOGRAM modules that docs present as available

The desktop source tree contains many CRYPTOGRAM-related modules, but several are still commented out of the build:

- `Telegram/CMakeLists.txt:605`
- `Telegram/CMakeLists.txt:615`
- `Telegram/CMakeLists.txt:635`
- `Telegram/CMakeLists.txt:651`
- `Telegram/CMakeLists.txt:653`
- `Telegram/CMakeLists.txt:690`
- `Telegram/CMakeLists.txt:733`

Currently commented out:

- `data/data_enhanced_privacy.cpp`
- `data/data_group_encryption.cpp`
- `data/data_location_randomization.cpp`
- `data/data_mls_protocol.cpp`
- `data/data_monero_miner.cpp`
- `data/data_quantum_storage.cpp`

At the same time, desktop docs still describe privacy, MLS, PQ, mining, and related modules as present features:

- `docs/features/desktop-features.md`
- `README.md`

Impact:

- The repo has desktop feature code, but not all of it is part of the built desktop target.
- The patch decision here is architectural: either re-enable and fix these modules, or narrow the docs and settings text to describe them as source-present but not currently shipped.

### P1: Android crypto docs need tighter wording around what is real, partial, and placeholder-based

The Android tree has more real implementation than earlier audits suggested:

- `TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp`
- `TMessagesProj/jni/cryptogram/data_signal_protocol.cpp`
- `TMessagesProj/jni/cryptogram/data_mls_protocol.cpp`
- `TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/`

What is clearly present:

- JNI entry points for Double Ratchet, MLS, and CRYPTOGRAM status.
- AES-GCM-backed per-session wrapper behavior in `CryptogramWrapper.cpp`.
- Full Signal/Double Ratchet-oriented native code in `data_signal_protocol.cpp`.
- MLS group state, member management, and message encrypt/decrypt paths in `data_mls_protocol.cpp`.
- Android settings UI and message-flow hooks in Java/Kotlin.

What still needs tighter claims:

- `CryptogramWrapper.cpp` reports state as an `"AES-256-GCM session"` rather than exposing full ratchet-state semantics.
- `data_mls_protocol.cpp:879` uses placeholder X448 generation.
- `data_mls_protocol.cpp:893`
- `data_mls_protocol.cpp:900`

Impact:

- Android docs should not describe the runtime path as fully audited end-to-end cryptography yet.
- The right phrasing is "present in code", "wired", "partial", and "requires runtime validation", not "complete" or "ready for deployment".

### P1: Post-quantum and hardware-backed-security claims are broader than the Android evidence

Current Android docs describe post-quantum and hardware-backed behavior as part of the feature story:

- `docs/features/android-features.md`
- `docs/features/security-overview.md`
- `docs/dev/SECURITY_STANDARDS.md`

Repository evidence is mixed:

- The Android JNI tree has strong classical crypto evidence for X25519, Ed25519, and AES-GCM in `data_signal_protocol.cpp`.
- The Android JNI tree does not show ML-KEM / ML-DSA implementation in the same way the desktop data tree does.
- Hardware-backed key comments exist in `data_signal_protocol.cpp`, but the repo does not include enough Android runtime evidence to claim device-proven KeyStore behavior from this snapshot alone.

Impact:

- Security docs should separate "desktop/source-tree PQ plumbing exists" from "Android runtime path proves PQ and hardware-backed deployment".
- This is a documentation-truth issue first; code work may follow depending on the intended Android scope.

### P1: Documentation navigation and dev notes still contain stale paths or stale status framing

The main docs have improved, but there are still stale references:

- `docs/README.md:39`
- `docs/README.md:40`
- `docs/dev/PULL_REQUEST.md:111`
- `docs/dev/PULL_REQUEST.md:399`

Observed issues:

- `docs/README.md` still lists `DOCKER_BUILD.md` and `GITHUB_ACTIONS_BUILD.md` as archived items by bare filename, while those files now live under `docs/archive/`.
- `docs/dev/PULL_REQUEST.md` still references `../../GITHUB_ACTIONS_BUILD.md`, which does not exist at repo root.
- `docs/dev/PULL_REQUEST.md` still uses old "complete end-to-end encryption" language and stale file inventory numbers.
- `docs/setup/` currently contains only `api_credentials.md`, so the docs index implies a fuller setup area than is actually present.

Impact:

- Users can still hit stale paths and outdated implementation language.
- This is a quick doc-cleanup pass, not a product-code blocker.

### P2: Existing audit/support docs are themselves partially stale

Two internal-facing audit/support docs no longer fully match the repo:

- `AUDIT_GAPS.md` (previous version)
- `docs/status/TEST_HARNESS_SCOPE.md`

Observed issues:

- The older gap report described the Android JNI layer as placeholder-only, which is no longer accurate.
- `docs/status/TEST_HARNESS_SCOPE.md` still tells readers to review wrapper placeholders in `CryptogramWrapper.cpp`, but the wrapper now contains concrete AES-GCM session handling and MLS group plumbing.

Impact:

- Future work should not rely on old audit text without revalidation.
- This audit file replaces the stale version; `TEST_HARNESS_SCOPE.md` should be updated in the first doc-truth patch pass.

## Documentation-to-Implementation Matrix

### Backed enough to keep, with tighter wording

- Android settings screen exists.
- Android settings toggles exist and are wired through `SharedConfig`.
- Android message flow has explicit encrypt/decrypt hook points.
- Android JNI surface exists for Double Ratchet and MLS.
- Desktop source tree contains advanced privacy/security modules.
- Desktop multi-platform build scripts and CI files exist.

### Present but partial, disabled, or weakly verified

- Android MLS implementation details for non-X25519 ciphersuites
- Android end-to-end cryptographic runtime validation
- Android post-quantum and hardware-backed deployment claims
- Desktop Double Ratchet enablement in settings
- Desktop MLS/group-encryption activation
- Desktop covert channel settings path
- Desktop Device Trust settings path

### Not supportable as currently documented

- "ALL TESTS PASSED" as a runtime-quality claim
- "READY FOR BUILD & DEPLOYMENT" from the current static harness alone
- "complete, production-quality implementation" for Android crypto
- Desktop claims that imply all advertised CRYPTOGRAM modules are currently compiled and shipped

## Recommended Patch Order

1. Fix status and implementation docs so they truthfully describe static verification vs runtime validation.
2. Reconcile desktop docs and settings text with what `Telegram/CMakeLists.txt` actually builds.
3. Decide Android truth boundary: either wire the remaining partial crypto paths or narrow the strongest claims.
4. Add real verification tiers: static checks, desktop unit tests, Android build, Android runtime/manual validation.
