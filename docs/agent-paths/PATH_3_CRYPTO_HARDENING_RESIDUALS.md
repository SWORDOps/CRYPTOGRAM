# AGENT PATH 3 — Desktop crypto hardening residuals

**Scope:** `Telegram/SourceFiles/data/data_covert_channel.cpp` (+ `.h`),
`Telegram/SourceFiles/security/universal_threat_detector.{h,cpp}`,
`Telegram/SourceFiles/settings/sections/settings_privacy_security.cpp`,
`tests/unit/`, `docs/`.
**Do NOT touch:** `data_enhanced_privacy.{cpp,h}` /
`data/enhanced_privacy_crypto.*` — the PBKDF2 upgrade there is IN FLIGHT by
another agent (the "CR2:" salted-envelope work). Do not touch
`telegram-android/**` (Paths 1–2).

## Objective

Close the three remaining hardening residuals from the roadmap (item 8),
each small, each independently testable:

1. **CNSA 2.0 alignment for the covert-channel HMAC chain.** The covert
   channel's packet authentication currently uses HMAC-SHA256 with
   HKDF-SHA256 key derivation. The project's military-trust tier documents
   CNSA 2.0 (SHA-384) as its compliance target. Align the WHOLE chain
   uniformly: HKDF digest SHA-384, HMAC-SHA-384, 48-byte derived keys.
   Uniformity is mandatory — do NOT mix SHA-256 and SHA-384 in the same
   derivation chain.
2. **UTD asset download progress surface.** The on-demand AI engine/model
   download (universal_threat_detector.cpp `downloadAssetsAsync`) reports
   progress only via qDebug. Surface it: add a
   `assetsDownloadProgress(QString stage, int percent)` signal (percent may
   be -1 for indeterminate) emitted from the worker at stage boundaries
   (engine fetched, model fetching x%, verified) and a
   `assetsDownloadFailed(QString error)` already exists as
   `modelLoadError` — keep using it. Then consume it in
   `settings_privacy_security.cpp`'s `BuildThreatDetectorSection`: add a
   status row under the AI toggle that shows "Downloading AI engine…",
   "Downloading model… 47%", or the last error, driven by the signals.
3. **UTD asset-host packaging runbook + guard.** The opt-in download points
   at `https://github.com/SWORDOps/CRYPTOGRAM/releases/download/
   ai-assets-v1` (overridable via `CRYPTOGRAM_ASSETS_URL` env /
   `CRYPTOGRAM_AI_ASSETS_URL`). Write `docs/ASSET_HOST_PACKAGING.md`: the
   exact file manifest expected at that URL (llama-server binary per
   platform naming, the three qwen2.5-*-utd-*.gguf models, `.sha256`
   sidecar format `<hex>  <filename>`), how to produce the sidecars
   (`sha256sum`), how to create the release with `gh release create
   ai-assets-v1 --title ... --notes ...` + `gh release upload`, and the
   env override. Note in the doc that publishing requires John's GitHub
   credentials — this is documentation, not an action.

## Verified background

- Covert channel: `data_covert_channel.cpp`. Current state after the
  merge-union fix (commit 9b66cd02f8 lineage): OpenSSL EVP HKDF-SHA256
  (`derivePacketSigningKey`, info "CovertChannel-PacketMAC", 32-byte
  output) + `computeHMAC` (manual RFC-2104 HMAC over SHA-256, block size
  64). The receiver side runs in the SAME binary (both parties run
  CRYPTOGRAM), so changing the parameters does not break third parties —
  but old-version peers would fail to verify new packets. Handle this:
  bump any covert-channel protocol/version marker if one exists, or gate
  the new parameters behind the quantum security level setting
  (>= Level 3 → SHA-384 chain) so it is a deliberate tier, matching how
  the rest of the file gates behavior.
- OpenSSL specifics that bit this codebase before: EVP HKDF requires the
  digest to be set (`EVP_PKEY_CTX_set_hkdf_md`) even in EXPAND_ONLY mode —
  missing it silently yields zero-filled output. HMAC via the
  `computeHMAC` helper: SHA-384 block size is 128 bytes — the manual
  RFC-2104 construction in that file takes the block size as a constant;
  change it together with the algorithm.
- UTD: `universal_threat_detector.h` declares the signals
  (`modelLoaded`, `modelLoadError`, …); `downloadAssetsAsync` runs in
  QtConcurrent with a fetch→verify chain (SHA-256 sidecar verification
  already implemented) and hops back via QMetaObject::invokeMethod. Add
  progress emission INSIDE the worker via the same invokeMethod pattern
  (never touch UI objects from the worker thread).
- Settings: `BuildThreatDetectorSection` in
  `settings_privacy_security.cpp` already builds the AI toggle + tier
  radios via `SectionBuilder::addControl` (do not regress to the removed
  `ctx.parent` pattern — that was a fixed bug).

## Verification gates (report outputs)

1. New standalone Catch2 test `tests/unit/test_covert_channel_sha384.cpp`
   (OpenSSL-only, CI-eligible — add to `tests/unit/CMakeLists.txt` AND the
   inline CMake in `.github/workflows/tests.yml` next to
   `test_e2e_x3dh_fixed`): derive the packet-signaling key per the NEW
   parameters, sign a packet, verify; assert the derived key is 48 bytes;
   assert a tampered packet fails verification; assert the SHA-256 →
   SHA-384 selection is level-gated (level < 3 → SHA-256 chain still
   self-consistent).
2. `bash run_tests.sh` and `bash run_e2e_tests.sh` PASS (they will not
   compile the covert channel, but must not regress).
3. Configure + build the Telegram target
   (`cmake -S . -B build_tests -G Ninja -DCMAKE_BUILD_TYPE=Release
   -DCRYPTOGRAM_BUILD_TESTS=ON -DCMAKE_PREFIX_PATH=$HOME/.local
   -DCRYPTOGRAM_ENABLE_COUNTERINTELLIGENCE=OFF` then
   `cmake --build build_tests --target Telegram -j$(nproc)`): zero errors.
4. Headless smoke: `timeout 25 ./build_tests/bin/Telegram -debug
   -platform offscreen` runs without new errors (UTD init line present).
5. `docs/ASSET_HOST_PACKAGING.md` exists with the manifest, sidecar
   format, and gh command sequence (documentation only — do NOT publish
   anything; publishing requires credentials).

## Guardrails

- Covert-channel wire compatibility is version-gated as described; do not
  silently change parameters for existing levels.
- Do not touch the PQE1 envelope, the ratchet spec, or any file under
  `telegram-android/`.
- The Settings status row must be driven by signals only — no polling, no
  threading changes in the settings UI.

## Report back

Files changed, the exact new derivation parameters (digests, sizes, infos),
test outputs, build/smoke outputs, the doc path, deviations with reasons.
