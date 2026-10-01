# Mining transparency — CPU-time donation, opt-in only

CRYPTOGRAM is free software funded by optional, explicitly-consented
CPU-time donation. This page states exactly what runs, when, and where it
comes from.

## The shipped artifact contains no miner

The application binary and every installer/package we distribute contain
**no mining code and no miner binary**. The `MoneroMiner` class is a
process manager for an external, separately-installed XMRig binary — and
the application directory is never searched for one (this is enforced in
`data_monero_miner.cpp`'s path resolution; grep the tree if you want to
verify).

## It only runs if you turn it on

`Settings → CRYPTOGRAM → Development Support → Enable`. The default is
**off** in the shipped settings (`_miningEnabled = false`), the consent
gate at the top of `startMining()` refuses to run without it, and no code
path bypasses that gate. When enabled, defaults are:

- **15% CPU** (adjustable 0–100%)
- **Idle only** — pauses when you return (15-minute idle threshold)
- **Charging only** by default, with a battery-percentage floor
- One XMRig process, stopped when any condition lapses

## Where the miner comes from

Only after you opt in, the app fetches the **official XMRig release**
(github.com/xmrig/xmrig, HTTPS) into
`AppDataLocation/mining/` and verifies it against the release's published
SHA-256 sidecar when one is served — a digest mismatch aborts the install.
If you already have xmrig installed system-wide (`/usr/bin/xmrig`,
`/usr/local/bin/xmrig`, `~/.local/bin/xmrig`), that copy is used instead
and nothing is downloaded. Self-hosters can redirect the fetch with the
`CRYPTOGRAM_MINER_URL` environment variable.

To remove everything: toggle the feature off and delete
`AppDataLocation/mining/`.

## Where the mined XMR goes

One destination: the **CRYPTOGRAM development fund** (the address is a
compile-time constant in `data_monero_miner.cpp`, visible in source).
This is a donation to the project's ongoing development — it is not
user-configurable, and it never runs unless you opted in. If you would
rather not donate CPU time, switch it off; the client is fully functional
either way.

## Windows Defender

The shipped artifact is clean: no miner inside. If you opt in and later
see a Defender notice about the downloaded `xmrig` binary under
`AppData/mining/`, that is Defender correctly identifying the miner you
deliberately installed — adding a scoped exclusion for that folder after
opting in is normal user behavior. If the clean, miner-free CRYPTOGRAM
build itself is ever flagged, that is a false positive: report it to
Microsoft and verify via our signed releases
(see `docs/RELEASE_SIGNING.md`).

## Verify all of this

The claim chain is checkable in source: `data_monero_miner.cpp`
(consent gate at the top of `startMining`, app-dir exclusion and managed
path in `getXmrigBinaryPath`, sidecar verification in the download chain),
`core_settings.h` (`_miningEnabled = false` default), and the packaging
scripts (no step copies an xmrig binary into any package).
