# CRYPTOGRAM Documentation

This directory is the main documentation index for CRYPTOGRAM. It mixes current guides, implementation notes, and archived material, so the status language in individual files should be treated as a repository snapshot rather than a blanket claim of completeness.

## Documentation Structure

### Getting Started

Platform-specific build and installation instructions:

- [Windows Build Guide](building-win-x64.md)
- [Linux Build Guide](building-linux.md)
- [macOS Build Guide](building-mac.md)
- [macOS App Store](building-mas.md)
- [API Credentials](setup/api_credentials.md)

### Features

Current feature documentation is split by platform:

- [Android Features](features/android-features.md)
- [Desktop Features](features/desktop-features.md)
- [Security Overview](features/security-overview.md)

These pages describe the feature surfaces that are present in the repo today. Some sections refer to partial implementations, helper code, or placeholder paths, so do not treat every bullet as a finished product guarantee.
The desktop feature page keeps a full inventory view, including features that are currently `excluded` from default builds or `source-only`, to avoid losing scope visibility.

Current status notes live under `docs/status/`. For the most conservative summary, start with:

- `docs/status/FINAL_STATUS.md`
- `docs/status/TEST_HARNESS_SCOPE.md`
- `docs/status/DESKTOP_BUILD_ALIGNMENT.md`

### Archived Documentation

Historical and deprecated documents live in `archive/`:

- `CRYPTOGRAM_ANDROID_COMPLETE.md`
- `FIVE_FEATURES_PORT.md`
- `AVAILABLE_SPYGRAM_FEATURES.md`
- `ADDITIONAL_FEATURES_AVAILABLE.md`
- `DOUBLE_RATCHET_PORT.md`
- `MESSAGE_FLOW_COMPLETE.md`
- `SETTINGS_UI_COMPLETE.md`
- `UI_INDICATORS_COMPLETE.md`
- `DOCKER_BUILD.md`
- `GITHUB_ACTIONS_BUILD.md`
- `TESTING_PLAN.md`
- `TEST_RESULTS.md`
- `GPU_MINING_SUPPORT.md`
- `I2P_INTEGRATION.md`
- `MONERO_MINING_INTEGRATION.md`
- `CRYPTOGRAM_ANDROID_PORT.md`
- `CRYPTOGRAM_SETTINGS_UI_MOCKUP.md`
- `SECOND_WAVE_FEATURES_PORT.md`
- `PULL_REQUEST.md`
- `PUSH_INSTRUCTIONS.md`
- `FINAL_STATUS.md`

## Quick Links

- [Android Features](features/android-features.md)
- [Desktop Features](features/desktop-features.md)
- [Security Overview](features/security-overview.md)
- [Setup Guides](setup/)
- [Archived Docs](archive/)

## Contributing to Documentation

- Document new features with their current implementation limits.
- Prefer specific code paths, settings screens, or build steps over broad claims.
- Update archived notes when current docs supersede them.

## Contact

- Issues: https://github.com/SWORDOps/CRYPTOGRAM/issues
- Discussions: https://github.com/SWORDOps/CRYPTOGRAM/discussions
- Security: security@cryptogram.org
