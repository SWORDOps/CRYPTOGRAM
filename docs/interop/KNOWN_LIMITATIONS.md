# CRYPTOGRAM — Live Interop Harness: Known Limitations

Scope: constraints of the desktop<->Android live E2EE verification harness
(`docs/interop/LIVE_EXCHANGE_RUNBOOK.md`, `scripts/interop/`). These are
documented constraints and verified current behaviors — not problems to paper
over inside the harness, and not license to patch protocol code.

## 1. The two one-time logins cannot be automated

Telegram login requires one phone number per client. Two test accounts must
be logged in ONCE by a human:

- Desktop session persists in `~/.local/share/Cryptogram/tdata`.
- Android session persists in the app's private data. `adb backup` is NOT
  reliable on modern Android — the supported persistence mechanism is the
  emulator quick-boot snapshot: always shut the emulator down WITHOUT
  `CRYPTOGRAM_WIPE=1` after logging in, so the snapshot keeps the session.

Until both logins exist, the harness dry-run is expected to show every
positive evidence row as PENDING and exit 0. That is the designed state, not
a fake pass.

## 2. Emulator constraints

- No Google Play services (the fork builds without them — that is fine), so
  push/notification paths are inert: the exchange MUST be
  foreground-foreground on both clients.
- The emulator needs Telegram DC reachability through the host network;
  blocked egress masquerades as "clients never come online" and must be
  ruled out before suspecting the protocol layer.
- AVD snapshots can contain logged-in sessions: AVD state lives under the
  emulator's own directory and must never be copied into or committed to the
  repository.

## 3. Pre-fix client incompatibility

Old (pre-9b66cd02f8/02527499ee) builds cannot bootstrap with new builds:
the desktop transport layout (zero-width `messageEntityUnknown` CRKE
entities) and the bundle format changed. Both clients in a live run must be
assembled from the same current main by `build_both.sh`. Mixed-version
first contact fails at bundle consumption (Android logs
`Failed to extract incoming key bundles` / shows `[🔐 Key exchange failed]`;
desktop logs a signature-verification failure) — record the pair of builds
when reporting any such failure.

## 4. Peer marking is asymmetric (verified, current build)

- Android gates 1:1 encryption on `EnhancedPrivacy.INSTANCE.isCryptogramUser`
  (native `gCryptogramUsers` map, filled by the first successful
  bundle-init / encrypt / decrypt with a peer). Marking is an automatic
  consequence of the first-contact bundle, not a UI action.
- Desktop does not gate the 1:1 Double Ratchet on any marking; session
  existence drives it. The desktop marking set
  (`EnhancedPrivacy::RegisterCryptogramUser`, fed only by
  `CovertChannel::registerCovertPeer -> AutoDetectCryptogramUser`) has no
  live caller in the current build — it affects the red-name display and
  group-encryption gating only. The runbook therefore requires no manual
  marking step for 1:1 scenarios.

## 5. Android session persistence is Path 2 (not merged)

Desktop persists Double Ratchet sessions under
`tdata/<account>/signal_protocol/`; the Android client keeps ratchet state
in native memory only. Until Path 2 lands, Scenario C (restart regression)
documents the CURRENT limitation: after an app restart Android re-bootstraps
(first outgoing message is plaintext + fresh bundle) and cannot decrypt the
desktop's next envelope until the session pair is rebuilt. The expected
observation is `Failed to decrypt desktop envelope` on Android right after a
restart — this is the documented limitation, not a harness failure.

## 6. Desktop PQ evidence is failure-only

`SignalProtocol::quantumWrapPayload` / `quantumUnwrapPayload`
(`data_signal_protocol.cpp`) log FAILURES only; a successful quantum wrap is
silent, so there is no `[PQ] wrap` success line to grep. Pass evidence for
the PQ leg is: `Signal Protocol [PQ]: generated KEM identity` present,
zero `[PQ]` failure lines, plus (once Path 1 lands) a successful Android
unwrap. `check_wire_evidence.sh` encodes exactly this.

## 7. ML-KEM (0x02) is desktop-only today

Android PQ parity is Path 1 (not merged at the time of writing). Scenario D
in the runbook is gated on a marker check
(`check_wire_evidence.sh --apk <apk>` greps the shipped
`libcryptogram.so` for KEM markers) and must be recorded as SKIPPED while
the gate prints PATH1-ABSENT. Today Android never advertises a KEM key, so
the desktop silently skips the wrap (no peer KEM key file) — absence of PQ
lines is expected in every scenario until Path 1 merges.

## 8. Static harnesses deliberately do NOT cover runtime crypto

`run_tests.sh`, the unit suites (test_e2e_x3dh_fixed, test_e2e_quantum_kem)
and this harness's greps prove code presence, conformance vectors and log
evidence — they cannot prove that two live clients decrypted each other's
traffic. Only the live exchange in the runbook does that, which is exactly
why the two human logins exist and must not be faked.

## 9. Log-fidelity caveats

- The JNI layer's `CryptogramNative` tag (`CryptogramWrapper.cpp`) is
  currently unused: LOGD/LOGE are defined but never called, so all Android
  runtime evidence comes from the Java tag `CryptogramMessageHelper`. The
  logcat filter keeps both tags.
- Desktop successes are mostly silent (see §6); several evidence rows are
  therefore "failure-only" rows whose PASS state is the absence of failure
  lines plus indirect positive markers.
- The desktop must run with `-debug` (or `CRYPTOGRAM_DESKTOP_LOG` pointed at
  a captured stderr) or the `Signal Protocol` lines are not emitted at all.
