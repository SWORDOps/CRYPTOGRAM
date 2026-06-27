# CRYPTOGRAM Desktop Features (Linux)

This page preserves the full desktop feature inventory and labels each item with current Linux status terms.  
Canonical source of truth: [Desktop Build Alignment Matrix](../status/DESKTOP_BUILD_ALIGNMENT.md).

Status terms used here:
- `included`: compiled into default Linux desktop build.
- `excluded`: present in source but not compiled by default.
- `source-only`: code exists but no active desktop build wiring.
- `partial`: runtime exists but end-to-end validation is incomplete.
- `experimental`: user-visible but not production-validated.

## Feature inventory

| # | Feature | Linux build status | Runtime status |
| --- | --- | --- | --- |
| 1 | Signal Protocol / Double Ratchet | included | partial — X3DH, Double Ratchet, AES-256-GCM wired; key bundle transport via MTProto init params + ZW message entities |
| 2 | MLS Protocol | included | partial — key package encode/decode, group encryption/decryption, Welcome transport via ZW entities; MLS key packages advertised in init params |
| 3 | Post-Quantum Cryptography | included | partial (hybrid plumbing present) |
| 4 | Audio Steganography and GNA | included | partial, experimental |
| 5 | Surveillance Detection | source-only | source-only/not shipped by default |
| 6 | Covert Channels | included | partial, experimental |
| 7 | Zero-Knowledge Authentication | included | partial, requires validation |
| 8 | Location Privacy and Randomization | excluded | not shipped by default |
| 9 | Counterintelligence (Canary and Honeypot) | included | partial, requires validation |
| 10 | NSA-Grade Security Architecture | included | partial, requires validation |
| 11 | Dead Man's Switch | included | partial, requires validation |
| 12 | Tor Integration (Snowflake) | included | partial, runtime wired |
| 13 | I2P Integration (Relay) | included | experimental, runtime wired |
| 14 | Bridge Support | included | partial, runtime wired |
| 15 | Monero Mining | included | optional, experimental, runtime wired |
| 16 | OpenVINO Translation | excluded | not shipped by default |

## Notes

- This is an inventory page, not a production-readiness claim.
- Items remain listed even when `excluded` or `source-only` so feature scope is visible without deletion.
- For operational claims, rely on matrix evidence links in `docs/status/DESKTOP_BUILD_ALIGNMENT.md`.
