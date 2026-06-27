# Building CRYPTOGRAM on Linux

Canonical desktop build entrypoint:

```bash
./build_linux.sh
```

This project does not use the old external `tdesktop` clone flow for primary builds in this repository snapshot.

## Prerequisites

- Linux environment with standard build tooling.
- Top-level `cmake` submodule populated as a real worktree, not just git metadata.
- Required files include:
  - `cmake/CMakeLists.txt`
  - `cmake/version.cmake`
  - `cmake/validate_special_target.cmake`
  - `cmake/options.cmake`
  - `cmake/external/qt/package.cmake`

If these are missing:

```bash
git -C cmake status --short
git submodule update --init --recursive cmake
```

If `git -C cmake status --short` shows mass `D` entries, the submodule git metadata exists but its worktree is empty; repopulate that worktree before retrying `./build_linux.sh`.

If the pinned submodule revision is unavailable upstream, desktop configure cannot proceed from this snapshot alone.

## Common build variants

```bash
# Release (default)
./build_linux.sh

# Debug
BUILD_TYPE=Debug ./build_linux.sh

# Custom build directory
BUILD_DIR=/tmp/cryptogram_build ./build_linux.sh

# Explicit parallelism
JOBS=8 ./build_linux.sh
```

## Output

- Typical binary location:
  - `build_release/bin/Telegram`
  - or `build_<type>/bin/Telegram` if custom `BUILD_TYPE`/`BUILD_DIR` is used.

## Wrapper scripts

- `build_all.sh`: extended desktop orchestrator/wrapper.
- `build_everything.sh`: interactive multi-target wrapper.

Use `build_linux.sh` for canonical Linux desktop documentation and CI examples.

## Status and claim gate

Before making feature-level claims, check:

- `docs/status/DESKTOP_BUILD_ALIGNMENT.md`
- `docs/features/desktop-features.md`
