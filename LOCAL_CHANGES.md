# Local Changes - DO NOT COMMIT

This file documents intentional local modifications that should **NOT** be committed.

## Submodule Modifications

The following submodules have local changes applied by `apply-build-patches.sh`:

### cmake (modified content)
- `external/tde2e/CMakeLists.txt` - Makes tde2e optional
- `external/webrtc/CMakeLists.txt` - Makes tg_owt optional

- `CMakeLists.txt` - Added for build integration

## Why These Are Local-Only

1. These submodules point to external repositories we don't control
2. The modifications are specific to CRYPTOGRAM's build requirements
3. Cannot push commits to upstream submodule repositories

## Git Status

Running `git status` will show:
```
Changes not staged for commit:
	modified:   cmake (modified content)
```

**This is normal and expected.** Do not attempt to commit or push these changes.

## To Apply These Changes

On a fresh clone, run:
```bash
./apply-build-patches.sh
```
