# CRYPTOGRAM — Design decisions sheet (freeze before next build)

**State:** all code paths from the four agent paths are implemented. The
builds you're looking at wait on the decisions below. Where a decision is
already locked, it's marked ✅ and restated so this sheet is the single
source of truth.

---

## 1. Android app identity (OPEN)

| Decision | Options | Recommendation |
|---|---|---|
| Package on your phone | a) Replace official Telegram (uninstall first — **secret chats on that phone are lost**, normal chats are cloud-safe) b) Coexist as `org.telegram.messenger.beta` alongside official (debug-signed builds only, nothing lost) | **b) now** (beta coexist build installed on emulator) → **a) for community feedback release**, per John: replace-official is the end goal, community feedback gates the full commitment |
| Launcher + in-app name | "Cryptogram" | ✅ "Cryptogram" (already in strings.xml) |
| Theme default on first launch | a) Follow system dark mode (off = standard light/blue) b) Always AMOLED black + red accent, day mode unchanged | **b)** — the client is a security tool; dark AMOLED is its identity. One-line change: force night theme selection on first launch, red accent already shipped as Dark Blue's default accent |
| Google sign-in | a) Keep the button, de-Googled builds fail it (the "ELF"/proto errors you saw are Google Play services rejecting our unregistered app identity — by design) b) Remove the Google button from login UI entirely | **b)** — phone-number login is the supported path; microG users can add Google login back themselves via microG's fingerprint registration |

## 2. Mining — CPU-time donation (LOCKED except as noted)

**Dev-fund wallet: `43jkTgxPyqDMbUaUdvQSNiMM7oyQVBpgg8GqKPCcrRKZH5BNNNKfCiafs5hqamWWWdj76YrpMxE7Bh2yMY6ztZKRKdgWJHq`** (John, 2026-09-30). Single destination — same address in README, settings UI, and the miner constant. No user override, no second destination.

| Decision | Status |
|---|---|
| Opt-in, default OFF | ✅ locked (`_miningEnabled = false`) |
| Default rate when opted in | ✅ 15% (your correction applied) |
| Single destination — dev fund wallet, not user-steerable | ✅ locked (compile-time constant, auditable in source) |
| Unbundled: app ships clean, official XMRig downloaded only after opt-in, checksum-verified | ✅ implemented (consent gate at top of `startMining()`, app-dir never searched, managed copy under AppDataLocation/mining) |
| **OPEN: pinned XMRig version + SHA-256** | Need: which XMRig release (e.g. v6.22.x) and whether you host the binary yourself on the asset host (recommended — then the digest is under your control) or pull from official XMRig GitHub releases (convenient, but you trust their release pipeline) |
| **Windows distribution** | ✅ **LOCKED (b)**: no donation mining on Windows at all — Windows gets the direct-donation wallet QR/button only. Linux/Android keep opt-in mining |

## 3. Quantum sessions (ratcheted quantum layer) — implemented, one item open

| Decision | Status |
|---|---|
| v2 envelope carries KEM ciphertext once per session; quantum chains advance per message | ✅ implemented desktop + Android lockstep |
| Per-message PQE1 remains the fallback for peers without quantum sessions | ✅ |
| **OPEN: YubiKey 5C FIPS management key** | Custom mgm key blocks slot-9c generation for the release signing key (PIN `49211337` verifies ✓). Options: a) provide the custom mgm key from your records b) PIV reset (wipes slot 9a Fast26 cert + slot 82 age identity — anything encrypted to that age identity becomes unreadable) c) sign with existing slot 9a identity (works, subject reads Fast26 Operator). **Awaiting your call** |

## 4. Signing / provenance

| Decision | Status |
|---|---|
| Android test builds | ✅ shared test keystore checked in, APK signed and installed on the emulator |
| Android release signing | ⚠️ blocked on §3 mgm key OR use existing slot 9a "Fast26 Operator" key (works with your PIN — signing via ykcs11 hit a JDK 21 routing issue that needs one focused session, solvable) |
| .deb / GitHub artifacts | OpenPGP detached signatures — script ready (`scripts/release/sign_deb.sh`), needs your OpenPGP signing subkey on the YubiKey OpenPGP app |
| CI | Builds unsigned + SHA256SUMS; signing ceremony stays local with the key present |

## 5. Desktop branding (OPEN, cosmetic but user-facing)

| Decision | Options | Recommendation |
|---|---|---|
| In-app name | a) Launcher/.deb already say CRYPTOGRAM; in-app title still says Telegram b) Full in-app rebrand (window titles, UI strings — large string surface, follow-up pass) | **a) now** (launcher + .deb name is what users see), b) as a follow-up pass |
| Theme | Desktop has night theme + accent support | Ship red accent default in a follow-up config pass |

---

## Already locked this session (restated)

- AI/UTD: opt-in default OFF, on-demand verified download, dynamic port
- PQE1 + ratcheted quantum sessions: desktop + Android lockstep, real ML-KEM
- Settings persistence: CRYP trailer, BOM/space-tolerant version parse
- Counterintelligence/GNA scaffolding: compiled out by default
- Interop harness: runbook + scripts + evidence matrix
- Test keystore: shared, checked in, clearly marked TEST ONLY

## Confirmed non-goals

- vmasm/byovd obfuscation for the miner — rejected
- Stealth mining / opt-out defaults — rejected
- CAC full DoD-chain validation — hardware-gated until a test card exists
