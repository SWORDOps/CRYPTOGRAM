# Committing Guidelines for CRYPTOGRAM

## Expected Git Status

When working on this repository, `git status` will **always** show:

```
Changes not staged for commit:
	modified:   cmake (modified content)
```

**This is intentional and correct.** These are local build patches documented in `LOCAL_CHANGES.md`.

## What NOT to Commit

**DO NOT commit or push:**
- Changes to the `cmake` submodule

These modifications must remain local-only because:
1. They are external repositories we don't control
2. The patches are specific to CRYPTOGRAM's build system
3. They are automatically applied by `./apply-build-patches.sh`

## What TO Commit

**DO commit and push:**
- Changes to `build_all.sh`
- Changes to documentation (*.md files)
- Changes to patches in `patches/` directory
- Any other files in the main CRYPTOGRAM repository

## For CI/CD and Automated Checks

These submodule modifications are documented and intentional:
- See `LOCAL_CHANGES.md` for full explanation
- See `.gitignore-local` for explicit note
- See `patches/README.md` for technical details

Automated checks should ignore uncommitted changes in:
- `cmake` submodule
