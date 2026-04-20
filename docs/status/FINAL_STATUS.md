# CRYPTOGRAM Current Status Snapshot

**Project**: CRYPTOGRAM Android/Desktop feature branch
**Date**: 2026-04-20
**Status**: Mixed implementation snapshot, not a completion claim

## Snapshot Summary

The repository contains a real Android CRYPTOGRAM feature surface, including settings UI, JNI bridge code, protocol classes, UI indicators, and native self-checks for key features. The codebase still contains partial or placeholder cryptographic paths, and some older docs describe stronger guarantees than the current runtime proof supports.

## Confirmed Surfaces

| Area | Current state |
| --- | --- |
| Android CRYPTOGRAM settings UI | Present |
| Double Ratchet / Signal hooks | Present, with native self-check support |
| MLS hooks | Present, with native self-check support and partial crypto paths |
| Privacy toggles | Present |
| Visual indicators | Present |
| Native bridge integration | Present |
| Desktop CRYPTOGRAM build modules | Present for core privacy/crypto modules |
| Device/runtime validation | Limited in-repo evidence |

## What Exists Today

### Android Integration

- CRYPTOGRAM settings screen in Telegram Android
- Toggle state and feature-status display
- Native wrapper classes for protocol and privacy helpers
- Message indicator helpers for encrypted chats
- Native self-check entry points for Double Ratchet and MLS availability

### Protocol and Privacy Code

- Double Ratchet-related classes and JNI entry points
- MLS-related classes and JNI entry points
- Privacy helper classes for hide-status style features
- Premium/test override hooks in settings-related code

### Desktop Documentation and Build-State Interpretation

The repository contains a broad desktop feature inventory and multiple security modules.  
Desktop claims should be interpreted through:

- `docs/status/DESKTOP_BUILD_ALIGNMENT.md` for `included` vs `excluded` vs `source-only`,
- `docs/features/desktop-features.md` for the full feature inventory with `partial`/`experimental` labels.

The inventory is intentionally preserved even for features that are not shipped by default, so scope visibility does not depend on deleting entries.

## Known Gaps

- Some JNI and native cryptographic paths still use partial or placeholder logic.
- Some documents describe stronger or more complete cryptographic behavior than the repository snapshot can prove end-to-end.
- Automated testing in-repo is limited relative to the size of the documentation surface.
- Device-specific verification is still necessary before treating the Android feature set as production complete.

## Test Coverage

The repository includes unit-test files for the CRYPTOGRAM feature set, but this snapshot does not support a claim of exhaustive validation. Use the tests as a starting point, not as proof that every documented path is covered.

## Build Notes

The Android build/docs are present under `docs/`, but the project still depends on the relevant Android toolchain and device-level validation to confirm runtime behavior.

## Recommended Language

When updating docs from here, prefer:

- "present in code"
- "documented"
- "partial"
- "placeholder path"
- "requires validation"

Avoid:

- "complete"
- "fully implemented"
- "ready for production"
- "100% tested"
