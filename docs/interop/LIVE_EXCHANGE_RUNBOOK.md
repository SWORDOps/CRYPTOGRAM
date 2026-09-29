# CRYPTOGRAM — Live Desktop<->Android E2EE Exchange Runbook

Purpose: verify, on real clients, the wire behavior that the unit/conformance
suites cannot prove: an actual message exchange between the desktop client
(`build_tests/bin/Telegram`) and the Android client
(`TMessagesProj_App` debug APK) over the Double Ratchet interop transport
(commits 9b66cd02f8 + 02527499ee).

Everything automatable is scripted under `scripts/interop/`. The two steps
that CANNOT be automated — the one-time Telegram logins on each client — are
marked **[HUMAN]**. Never fake them; a run with pending logins must stay
pending in the evidence matrix.

Companion doc: `docs/interop/KNOWN_LIMITATIONS.md`.

---

## 1. Prerequisites

### 1.1 Builds

```bash
./scripts/interop/build_both.sh
```

Artifacts (script prints path/size/sha256 and fails non-zero on error):

| Client  | Artifact |
|---------|----------|
| Desktop | `build_tests/bin/Telegram` |
| Android | `telegram-android/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk` (contains `lib/*/libcryptogram.so`) |

Both clients MUST come from the same source state (current main). Mixing a
pre-fix client with a post-fix client breaks first-contact bootstrap — see
KNOWN_LIMITATIONS §3.

### 1.2 Emulator

```bash
./scripts/interop/launch_emulator.sh
```

Boots AVD `$CRYPTOGRAM_AVD` (default `cryptogram_api35`, created from
`system-images;android-35;google_apis;x86_64` on first use), waits for
`sys.boot_completed`, `adb install -r` the APK, launches the launchable
activity read from the APK.

### 1.3 One-time account logins — **[HUMAN]** (cannot be automated)

Telegram requires one phone number per client. Prepare TWO test accounts
(two eSIM/VoIP numbers) and log in ONCE:

- **Desktop [HUMAN]**: run `./build_tests/bin/Telegram -debug` (add
  `-platform offscreen` for headless hosts) and complete the phone +
  code login. Sessions persist under `~/.local/share/Cryptogram/tdata`
  (per-account data in the account's own subdirectory). Do NOT run with a
  fresh `-wipe-data`-style reset afterwards; the tdata IS the session.
- **Android [HUMAN]**: on the emulator, open the app and complete login.
  Sessions persist in the app's private data. `adb backup` is NOT a reliable
  persistence mechanism on modern Android — keep the AVD snapshot instead:
  close the emulator WITHOUT `CRYPTOGRAM_WIPE=1` so the quick-boot snapshot
  retains the logged-in state. Never copy AVD state into the repo.

No real credentials, phone numbers or session data may ever be committed.

### 1.4 In-client toggles

Both clients must have the Double Ratchet enabled before the exchange:

- Desktop: **Settings -> CRYPTOGRAM -> encryption** (double ratchet on).
- Android: **Settings -> Cryptogram -> Double Ratchet** on
  (`SharedConfig.cryptogramDoubleRatchet`). Without it,
  `CryptogramMessageHelper` passes every message through as plaintext.

### 1.5 Peer marking (verified mechanics — read before first contact)

The two sides use DIFFERENT gating today; do not assume symmetric marking:

- **Android** gates encryption on `EnhancedPrivacy.INSTANCE.isCryptogramUser
  (userId)`, backed by a native map filled as a side effect of the first
  successful `initializeWithRemoteBundle` / `encrypt` / `decrypt` for that
  peer (`CryptogramWrapper.cpp`, `gCryptogramUsers`). Consequence: the exact
  bootstrap step that marks a peer is **receiving the desktop first-contact
  message carrying the invisible key-bundle entity** (or any successful
  encrypt/decrypt with that peer). There is no manual "mark as Cryptogram
  user" UI action required on Android.
- **Desktop** does NOT gate the 1:1 Double Ratchet on a user marking. The
  send path (`apiwrap.cpp`, outgoing message hook) attaches the desktop key
  bundle when no session exists and encrypts as soon as one does. The
  `EnhancedPrivacy::RegisterCryptogramUser`/`IsCryptogramUser` set on desktop
  (red-name display, group-encryption gating) is only fed by
  `CovertChannel::registerCovertPeer -> AutoDetectCryptogramUser`, which has
  no caller on the current build — see KNOWN_LIMITATIONS §4.
- Practical consequence: **the first message in each direction is
  plaintext + invisible bundle**. Keep exchanging; encrypted traffic only
  starts after the bundle handshake completes (per-scenario details below).

### 1.6 Networking

The emulator must reach the Telegram MTProto DCs over the host network (NAT
default). A corporate proxy or blocked egress shows up as the clients never
coming online; verify with `adb shell ping` to any public host and by seeing
the desktop client connect before blaming the protocol layer.

### 1.7 Foreground requirement

The fork builds without Google Play services; push/notification paths are
inert. Keep BOTH clients foreground during every exchange. On the emulator,
do not let it lock the screen mid-exchange (`adb shell svc power stayon true`
helps).

---

## 2. Harness scripts

| Script | Role |
|--------|------|
| `scripts/interop/build_both.sh` | incremental desktop + Android builds, artifact report |
| `scripts/interop/launch_emulator.sh` | AVD create/boot, APK install, app launch |
| `scripts/interop/collect_logs.sh` | desktop log tail + filtered logcat into `artifacts/interop-logs/` (NEVER commit that dir) |
| `scripts/interop/check_wire_evidence.sh <desktop-log> <logcat-file> [--apk <apk>]` | PASS/FAIL/PENDING evidence matrix over the captured logs |

Wire-surface reference (exact log strings, verified in source):

| Event | Client | Log line (tag / file) |
|-------|--------|----------------------|
| Own PQ KEM identity ready | Desktop | `Signal Protocol [PQ]: generated KEM identity %1` |
| Incoming bundle signature BAD | Desktop | `Signal Protocol: Incoming key bundle signature verification failed for peer %1` |
| Session from remote bundle | Desktop | silent on success; failure: `Signal Protocol Error: Remote key bundle signature verification failed in createSession for peer %1` |
| Receiver-side session | Desktop | `Signal Protocol: Receiver-side session created for peer %1` |
| Send without session | Desktop | `Signal Protocol: No session for peer %1` |
| PQ wrap/unwrap failures | Desktop | `Signal Protocol [PQ]: encapsulation failed / unwrap failed / no local KEM identity available / peer key import failed` |
| Outgoing bundle attached | Android | `Attached desktop key bundle for user %d (%d bytes)` (tag `CryptogramMessageHelper`) |
| Encrypted outgoing | Android | `Encrypted message for user %d (%d bytes)` |
| Decrypted desktop envelope | Android | `Decrypted desktop envelope from user %d` |
| Envelope decrypt failure | Android | `Failed to decrypt desktop envelope` |
| Incoming bundle failure | Android | `Failed to extract incoming key bundles` |
| JNI layer | Android | tag `CryptogramNative` — defined in `CryptogramWrapper.cpp` but currently unused (no LOGD/LOGE call sites) |

Desktop success paths are mostly SILENT (only failures log); the evidence
matrix accounts for this — absence of failure lines plus the positive lines
above is the pass signal.

---

## 3. Scenario A — desktop initiates

Clean state: fresh test accounts have no prior sessions. Re-runs need the
session reset from §7.

1. Start the desktop client with debug logging:
   `./build_tests/bin/Telegram -platform offscreen -debug 2>&1 | tee /tmp/desktop-stderr.log`
2. Boot emulator + app (`launch_emulator.sh`). Start a logcat capture in a
   second terminal (optional; `collect_logs.sh` can also dump at the end):
   `adb logcat -v time -s CryptogramMessageHelper:V CryptogramNative:V`
3. Desktop: open the 1:1 chat with the Android account, send `interop-A1`.
   - Wire: **plaintext + invisible key-bundle entity** (ZW chars ride as a
     `messageEntityUnknown`; `apiwrap.cpp` send hook,
     `attachKeyBundleIfNeeded`).
   - Visible (desktop): normal text. No "No session" error expected.
4. Android: the message arrives, the bundle is consumed silently
   (`extractIncomingBundles` -> `initializeFromDesktopBundle`; peer is now
   marked as a Cryptogram user). Visible (Android): `interop-A1` with no
   zero-width garbage. If the desktop message had carried ONLY the bundle,
   Android shows the placeholder
   `[🔐 Key exchange completed. Send one more message to finalize secure session.]`.
5. Android: reply `interop-A2`.
   - Expected logcat: `Encrypted message for user <android-id> (N bytes)`.
   - Wire: desktop-alphabet encrypted envelope.
6. Desktop: receives the envelope; `processIncomingMessage` cannot decrypt
   (first contact) and re-establishes from the registered bundle:
   - Expected desktop log: `Signal Protocol: Receiver-side session created
     for peer <desktop-peer-id>`.
   - Visible (desktop): `interop-A2`.
7. Desktop: send `interop-A3`. Now a session exists -> encrypted send.
   PQ wrap is SILENTLY skipped (Android advertises no KEM key until Path 1);
   no `[PQ]` failure lines are expected. Visible: normal text.
8. Android: expected logcat `Decrypted desktop envelope from user <id>`;
   visible: `interop-A3`.

**Pass criteria (Scenario A)**

- logcat contains BOTH `Encrypted message for user` and
  `Decrypted desktop envelope from user`.
- desktop log contains `Receiver-side session created for peer`.
- NEITHER log contains any of: bundle signature verification failed,
  `Failed to decrypt desktop envelope`, `Failed to encrypt message`,
  `[PQ]: ...failed`.
- Messages A1..A3 render as typed on both screens (no ZW garbage).
- `check_wire_evidence.sh` reports: `desktop.session.created` PASS,
  `android.encrypt.out` PASS, `android.decrypt.desktop` PASS, all
  failure-only rows OK-ABSENT, zero FAIL.

---

## 4. Scenario B — Android initiates

Mirrored first contact; reset session state per §7 first.

1. Android: open the 1:1 chat with the desktop account, send `interop-B1`.
   - Android has no session -> plaintext + attached bundle.
   - Expected logcat: `Attached desktop key bundle for user <id> (N bytes)`.
2. Desktop: receives; `history_item.cpp` extracts the CRKE entities, calls
   `registerRemoteKeyBundle` then, because no session exists,
   `createSession(peer, bundle)` (desktop becomes the sender side).
   - Expected desktop log: silent success; specifically NO
     `Remote key bundle signature verification failed` line.
   - Visible (desktop): `interop-B1` (invisible payload stripped).
3. Desktop: reply `interop-B2`. Session exists -> encrypted send.
4. Android: expected logcat `Decrypted desktop envelope from user <id>`;
   visible: `interop-B2`.
5. Android: send `interop-B3` -> `Encrypted message for user <id>`; desktop
   decrypts (silent) and renders it.
6. Note: in this direction the desktop session came from
   `createSession(peer, bundle)` (silent), NOT from the lazy receiver-side
   path; `Receiver-side session created` appears only if that first session
   failed to decrypt and the recovery path re-established it. Absence of the
   line in Scenario B is normal.

**Pass criteria (Scenario B)**

- logcat: `Attached desktop key bundle for user` AND
  `Encrypted message for user` AND `Decrypted desktop envelope from user`.
- desktop log: NO bundle signature verification failures.
- B1..B3 render as typed on both screens.

---

## 5. Scenario C — restart / persisted-session regression

After Scenario A or B has completed and traffic flows encrypted:

1. Quit the desktop client cleanly; force-stop the app:
   `adb shell am force-stop <package>` (package name is printed by
   `launch_emulator.sh`; snapshot-preserve the emulator — do NOT wipe).
2. Relaunch both clients.
3. Desktop -> Android: send `interop-C1`.
   - Desktop persists sessions (`tdata/<account>/signal_protocol/`);
     expected: envelope sent with the persisted session.
   - **CURRENT LIMITATION (Path 2 not merged)**: Android holds ratchet
     sessions in native memory only and re-bootstraps on restart, so C1 is
     EXPECTED TO FAIL to decrypt on Android
     (`Failed to decrypt desktop envelope`). This documents the limitation;
     it is not a harness defect. See KNOWN_LIMITATIONS §5.
4. Android -> desktop: send `interop-C2`.
   - Android has no session -> plaintext + fresh bundle again.
   - Desktop registers the fresh bundle; its old session still exists, so
     the conversation stays out of sync until the desktop peer-session state
     is reset (§7) or Path 2 lands.
5. Record the observed rows in the evidence matrix; for a green regression
   run after Path 2, both C1 and C2 must decrypt WITHOUT a re-bootstrap
   (no new `Attached desktop key bundle` line after restart).

---

## 6. Scenario D — post-quantum layer (CONDITIONAL on Path 1)

Gate first:

```bash
./scripts/interop/check_wire_evidence.sh \
    artifacts/interop-logs/desktop-log-tail.txt \
    artifacts/interop-logs/logcat-cryptogram.txt \
    --apk telegram-android/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk
```

The `Path 1 gate` line reports PATH1-MERGED (KEM markers found in the APK's
`libcryptogram.so`) or PATH1-ABSENT. On the current main the gate prints
PATH1-ABSENT — Android ML-KEM parity is Path 1 — and this scenario is
SKIPPED (record it as SKIPPED, not FAIL).

If Path 1 IS merged (future main):

1. Android's advertised bundle must carry the 0x02 KEM extension; the desktop
   persists it (`registerRemoteKeyBundle` -> per-peer KEM key file). Verify on
   desktop after first contact: no `[PQ]: failed to persist peer KEM key`.
2. Desktop sends an encrypted message.
   - Expected: quantum wrap succeeds **silently** — the desktop logs PQ
     FAILURES only. The brief's anticipated `[PQ] wrap` success line does not
     exist in `data_signal_protocol.cpp`; pass evidence is the ABSENCE of
     `[PQ]: encapsulation failed / peer key import failed / no local KEM
     identity available` combined with a successful Android unwrap.
   - If Path 1 is absent-but-advertised (never expected): the failure lines
     above WOULD appear — capture and STOP, that is a defect (report, do not
     patch).
3. Android receives: the PQE1-framed inner payload must unwrap before the
   ratchet decrypt; expected logcat `Decrypted desktop envelope from user`.
4. Matrix rows for this scenario: `desktop.pq.identity` PASS,
   `desktop.pq.failures` OK-ABSENT, `android.decrypt.desktop` PASS.

---

## 7. Resetting session state between runs

The handshake is only "first contact" while NO session exists on either
side. To re-run Scenario A or B cleanly:

- Desktop: with the client CLOSED, delete the peer's session state under the
  account directory: `~/.local/share/Cryptogram/tdata/<account>/signal_protocol/`
  (whole directory; it only holds signal session/key files — do not touch the
  rest of tdata, that is the login).
- Android: app data hold the sessions in native memory — clear via
  `adb shell pm clear <package>` (requires re-login [HUMAN]) or simply
  re-install the APK over a wiped data partition (also [HUMAN] re-login).
  Prefer doing resets BEFORE the one-time logins, or budget a re-login.

## 8. Collecting and judging evidence

```bash
CRYPTOGRAM_DESKTOP_LOG=/tmp/desktop-stderr.log ./scripts/interop/collect_logs.sh
./scripts/interop/check_wire_evidence.sh \
    artifacts/interop-logs/desktop-log-tail.txt \
    artifacts/interop-logs/logcat-cryptogram.txt \
    --apk telegram-android/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk
```

Expected DRY-RUN output (before the [HUMAN] logins): all positive rows
PENDING, failure-only rows OK-ABSENT, `Summary: PASS=n FAIL=0` and exit 0.
Any FAIL row = a real wire defect was observed: STOP, capture
`artifacts/interop-logs/`, and report it — protocol defects found here are
high-value findings, never something to patch silently.

Remember: `artifacts/interop-logs/` may contain peer ids / phone numbers —
never commit it.
