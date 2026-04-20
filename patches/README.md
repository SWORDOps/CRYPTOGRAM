# Local Build Patches

These patches contain local modifications required for building CRYPTOGRAM that are **intentionally not committed to submodules**.

## Why Local-Only?

- We don't have write access to push commits to those upstream repos
- The modifications are specific to CRYPTOGRAM's build requirements

## What's Changed?

1. **cmake-optional-libs.patch**: Makes `tde2e` and `tg_owt` optional in packaged mode
   - Modifies: `cmake/external/tde2e/CMakeLists.txt`
   - Modifies: `cmake/external/webrtc/CMakeLists.txt`


## How to Apply

Run the script from the repository root:
```bash
./apply-build-patches.sh
```

Or apply manually:
```bash
cd cmake
git apply ../patches/cmake-optional-libs.patch
```

## Note

Git will show these as uncommitted changes. **This is intentional and expected.**
Do not commit these changes to the main CRYPTOGRAM repository.
