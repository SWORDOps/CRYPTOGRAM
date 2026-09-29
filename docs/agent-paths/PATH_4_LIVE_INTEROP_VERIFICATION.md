# AGENT PATH 4 — Live interop verification harness

**Scope:** `scripts/interop/` (new), `docs/interop/` (new),
`tests/` additions, `run_tests.sh` (one require_file block at most).
**Do NOT touch:** protocol crypto (`data_signal_protocol.cpp`,
`InteropCore.*`, `CryptogramWrapper.cpp` protocol sections — report defects,
do not patch), `data_enhanced_privacy.*` (in-flight elsewhere).

## Objective

The desktop↔Android E2EE interop (commits 9b66cd02f8 + 02527499ee) is
conformance-proven at the unit level but has never exchanged a real message
between a real desktop client and a real Android client. Build the
repeatable verification harness for that exchange, automate every step that
CAN be automated, and document the two steps that cannot (one-time account
logins). Deliverables:

1. `docs/interop/LIVE_EXCHANGE_RUNBOOK.md` — the manual runbook.
2. `scripts/interop/` — helper scripts for every automatable step.
3. A `docs/interop/KNOWN_LIMITATIONS.md` capturing the constraints below.

## Verified background (current state)

- Desktop: `build_tests/bin/Telegram` builds and boots headless
  (`-platform offscreen`); the PQ/ratchet layers are conformance-tested
  (test_e2e_x3dh_fixed: 590 assertions; test_e2e_quantum_kem: 50). Debug
  logging via `-debug`; log output also lands in the log file.
- Android: `telegram-android` assembles via
  `cd telegram-android && ANDROID_HOME=$HOME/Android/Sdk
  ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018 ./gradlew
  :TMessagesProj_App:assembleAfatDebug --no-daemon` (~1h45 first time,
  incremental after). APK output:
  `TMessagesProj_App/build/outputs/apk/afat/debug/app.apk` (contains
  `lib/*/libcryptogram.so`). An emulator toolchain exists
  (android-emulator MCP tools or manual avdmanager/emulator with
  SDK at `$HOME/Android/Sdk`).
- Wire surface (what to look for in logs):
  - Desktop incoming bundles: "Signal Protocol: Incoming key bundle
    signature verification" log region in
    `data_signal_protocol.cpp` (`processIncomingKeyBundle`);
    establishment: "Receiver-side session created for peer";
    PQ layer: "Signal Protocol [PQ]" lines (wrap/unwrap/failure).
  - Android: `CryptogramMessageHelper` Log.d tags ("Encrypted message
    for user", "Decrypted desktop envelope from user") and
    `InteropCore` path via logcat (`adb logcat -s cryptogram` — confirm
    the actual tag in `CryptogramWrapper.cpp`).
- KNOWN CONSTRAINTS (document, do not paper over):
  - Telegram login requires a phone number per client. Two test accounts
    (e.g. two eSIM/voip numbers) must be logged in ONCE by a human; the
    session files then persist (`~/.local/share/Cryptogram/tdata` on
    desktop; the app's private data on Android — back up/restore via
    `adb backup` is NOT reliable on modern Android; instead keep the
    emulator snapshot).
  - The emulator's Android client needs Google Play services absent is
    fine (Telegram forks build without them) but push/notification paths
    are inert — exchange must be foreground-foreground.
  - First-contact flow: desktop sends plaintext + invisible bundle entity;
    Android replies (establishing Bob-side); THEN encrypted traffic flows.
    The runbook must walk exactly this and the equivalent
    Android-initiated direction.
  - ML-KEM (0x02) is desktop-only today (Android parity is Path 1) — the
    runbook's PQ assertions are conditional on Path 1 being merged; gate
    those steps on a marker (grep the APK's InteropCore for the KEM symbol
    or version check) and mark them "if Path 1 merged".

## Tasks

1. **Runbook** (`docs/interop/LIVE_EXCHANGE_RUNBOOK.md`), sections:
   - Prerequisites: two Telegram accounts logged in once (desktop test
     profile + emulator), both clients from the same build (current main),
     DRC toggle paths (desktop Settings → CRYPTOGRAM → encryption; Android
     Settings → Cryptogram → Double Ratchet), and the peer-marking step
     (each side must have the other marked as a Cryptogram user — verify
     how marking happens: Android `EnhancedPrivacy.INSTANCE.isCryptogramUser`
     gate; document the exact UI/bootstrap step that marks it).
   - Scenario A (desktop initiates): expected observable sequence with the
     log lines above at each step, the visible behavior in each client
     (first message plaintext + invisible bundle; second message
     encrypted), and the pass criteria.
   - Scenario B (Android initiates): mirrored.
   - Scenario C (regression): after a session exists, kill and restart
     both clients; verify persisted-session traffic still decrypts
     (desktop persists sessions; Android persistence is Path 2 — if not
     merged, this scenario documents the CURRENT limitation: Android
     re-bootstraps on restart).
   - Scenario D (PQ, conditional on Path 1): desktop log must show
     "[PQ] wrap" on send and Android must unwrap; failure text expected if
     Path 1 absent.
2. **Scripts** (`scripts/interop/`):
   - `build_both.sh` — desktop incremental build + Android incremental
     assembleDebug with the env from above; exits non-zero on failure;
     prints artifact paths.
   - `launch_emulator.sh` — boots the AVD (name via env
     `CRYPTOGRAM_AVD`, create via avdmanager if absent), waits for
     sys.boot_completed, installs `app.apk`, launches the app activity.
   - `collect_logs.sh` — captures desktop debug log tail + `adb logcat -d`
     filtered to the cryptogram tags into `artifacts/interop-logs/`.
   - `check_wire_evidence.sh <desktop-log> <logcat-file>` — greps the
     expected lifecycle lines (bundle verified → session created → PQ
     wrap/unwrap → decrypted) and prints a PASS/FAIL evidence matrix.
     Pure grep/sed; no magic.
3. **Known limitations doc** — the constraints section above expanded,
   plus: emulator networking (Telegram DC reachability), the pre-fix
   client incompatibility (old builds cannot bootstrap with new), and the
   fact that static harnesses deliberately do NOT cover runtime crypto.
4. **Harness wiring:** add the scripts existence to `run_tests.sh`'
   required files (2-3 `require_file` entries) so the harness tracks them.

## Verification gates (report outputs)

1. `build_both.sh` completes (desktop binary + APK exist; report sizes).
2. `launch_emulator.sh` boots, installs, launches (report adb output).
3. `collect_logs.sh` + `check_wire_evidence.sh` run to completion against
   the CURRENT state (no live accounts yet — the matrix will show which
   steps are pending human login; that is the expected output).
4. Both harnesses still PASS; the new require_file entries pass.

## Guardrails

- No protocol changes. If the live exchange reveals a protocol defect,
  STOP, capture the evidence, and report — defects found here are high-
  value findings, not things to patch silently.
- No real credentials, phone numbers, or session data committed anywhere.
- Emulator snapshots may contain logged-in sessions: never commit emulator
  state; keep it under the emulator's own directory.

## Report back

Files created, build/boot outputs, the evidence matrix from a dry run
(pre-login), the runbook's final step list, deviations with reasons.
