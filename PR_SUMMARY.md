# Pull Request: Improve build_all.sh - Fix Verification and Permission Issues

## Branch
`claude/build-ada-protobuf-01Tpe3rvKAkdWnRVGPd3uLET`

## Summary

This PR fixes critical bugs in `build_all.sh` that were causing:
1. **False positive verification** - Protobuf installation always reported success even when it failed
2. **Permission conflicts** - Multiple users couldn't run builds due to shared log directories
3. **Unbound variable errors** - Script failed with "unbound variable" errors due to `set -u`

## Commits

### 1. Improve Ada and Protobuf installation verification (609762e)

**The Bug:**
The Protobuf verification used this logic:
```bash
if find /usr -name 'libprotobuf.so*' 2>/dev/null | head -n1; then
    print_warning "Using system Protobuf"
else
    fail "Protobuf installation verification failed"
fi
```

This **always succeeded** because `find | head` returns exit code 0 even when finding nothing.

**The Fix:**
```bash
SYSTEM_PROTO=$(find /usr -name 'libprotobuf.so*' -o -name 'libprotobuf.a' 2>/dev/null | head -n1)
if [ -n "$SYSTEM_PROTO" ]; then
    print_warning "Found system Protobuf at: $SYSTEM_PROTO"
    print_warning "Using system Protobuf instead"
else
    print_error "Protobuf installation verification FAILED"
    # ... detailed diagnostics ...
    fail "Protobuf installation verification failed - no libraries found"
fi
```

Now properly checks if the variable is non-empty.

**Additional Improvements:**
- Clear "PASSED/FAILED" messaging for both Ada and Protobuf
- Detailed diagnostic output on failure showing:
  - Expected library location
  - Directory permissions
  - Directory contents
- State only saved after successful verification
- Better error messages for troubleshooting

### 2. Fix log directory permission issues (3763ea8)

**The Problem:**
```
./build_all.sh: line 101: /tmp/cryptogram_builds/build_*.log: Permission denied
```

When the script ran as root, it created `/tmp/cryptogram_builds` owned by root. When a regular user tried to run it, they got permission denied errors.

**The Solution:**
Changed from shared directory to user-specific:
- Old: `/tmp/cryptogram_builds` (shared, causes conflicts)
- New: `/tmp/cryptogram_builds_${USER}` (isolated per user)

**Fallback mechanism:**
If `/tmp` is not writable, falls back to `$HOME/.cache/cryptogram_builds`

**Benefits:**
- Root and regular users can both run builds without conflicts
- Each user gets their own isolated log directory
- Respects `LOG_DIR` environment variable for custom locations
- Clear error messages if log directory is not writable

### 3. Fix unbound variable errors with set -u (2033374)

**The Problem:**
Script has `set -Eeuo pipefail` which includes `set -u` (nounset). This causes errors when referencing unbound variables:
```
./build_all.sh: line 62: LOG_DIR: unbound variable
```

Three critical issues:
1. `LOG_DIR` check failed when not set in environment
2. `CC/CXX` could be unbound if no compiler found
3. Export statements tried to export potentially unbound variables

**The Solution:**

1. **LOG_DIR check (line 63):**
   ```bash
   # Before
   if [ -z "$LOG_DIR" ]; then

   # After
   if [ -z "${LOG_DIR:-}" ]; then
   ```
   Parameter expansion with empty default prevents unbound error

2. **Compiler detection (lines 459-481):**
   ```bash
   # Initialize before loops
   CC=""
   CXX=""

   # Check with safe parameter expansion
   [ -z "${CC:-}" ] && fail "No C compiler found"
   [ -z "${CXX:-}" ] && fail "No C++ compiler found"

   # Export after validation
   export CC
   export CXX
   ```

**Benefits:**
- Script works correctly with strict mode (`set -u`)
- No false errors when environment variables aren't pre-set
- Cleaner error messages when compilers aren't found

### 4. Add verification tests (149981d & 2033374)

Created `test_build_fixes.sh` to verify all fixes work correctly.

**Tests included:**
1. ✓ Log directory path generation with user-specific paths
2. ✓ Log directory writability checks
3. ✓ Log file creation permissions
4. ✓ Protobuf verification logic fix (demonstrates old vs new behavior)
5. ✓ User isolation - different users get separate directories
6. ✓ Verification message format (PASSED/FAILED)
7. ✓ Diagnostic output on installation failures
8. ✓ Unbound variable protection with safe parameter expansion

All tests pass! ✓

## How to Verify

Run the test suite:
```bash
./test_build_fixes.sh
```

Expected output:
```
═══════════════════════════════════════
All tests passed! ✓
═══════════════════════════════════════

Changes verified:
  1. User-specific log directories prevent permission conflicts
  2. Protobuf verification logic correctly detects missing libraries
  3. Clear PASSED/FAILED messaging for installations
  4. Detailed diagnostics on failures
  5. No unbound variable errors with set -u
```

## Files Changed

```
 PR_SUMMARY.md       | 160 ++++++++++++++++++++++++++++++++++
 build_all.sh        | 132 +++++++++++++++++++++++++++---
 test_build_fixes.sh | 137 ++++++++++++++++++++++++++++++
 3 files changed, 401 insertions(+), 28 deletions(-)
```

## Testing Performed

- ✅ Verified Ada and Protobuf installation verification works correctly
- ✅ Tested with both root and regular user accounts
- ✅ Confirmed fallback to user cache directory works
- ✅ Validated error messages provide useful diagnostics
- ✅ Tested with unset environment variables (LOG_DIR, CC, CXX)
- ✅ Confirmed script works with strict mode (`set -u`)
- ✅ All 8 automated tests pass

## Impact

**Before:**
- Protobuf verification always succeeded (false positive)
- Permission denied errors when switching users
- Unbound variable errors with strict mode
- Difficult to diagnose installation failures

**After:**
- Protobuf verification correctly detects failures
- Each user has isolated log directory
- Script works correctly with `set -u` (strict mode)
- Clear diagnostics show exactly what went wrong
- Multiple users can run builds on same system

## Breaking Changes

None - this only fixes bugs and improves error messages.

## Environment Variable Support

Users can override log directory:
```bash
export LOG_DIR=/path/to/custom/logs
./build_all.sh
```

## Create the PR

Visit: https://github.com/SWORDOps/CRYPTOGRAM/pull/new/claude/build-ada-protobuf-01Tpe3rvKAkdWnRVGPd3uLET

Use this PR title:
```
Improve build_all.sh: Fix verification and permission issues
```

Copy the content above into the PR description.
