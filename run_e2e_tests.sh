#!/usr/bin/env bash

set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

pass_count=0
fail_count=0
skip_count=0
total_tests=0

log_pass() {
    printf '[PASS] %s\n' "$1"
    ((pass_count++))
}

log_fail() {
    printf '[FAIL] %s\n' "$1"
    ((fail_count++))
}

log_skip() {
    printf '[SKIP] %s\n' "$1"
    ((skip_count++))
}

echo "======================================"
echo "CRYPTOGRAM E2E Test Battery"
echo "Full end-to-end verification suite"
echo "======================================"
echo

# ─── Phase 1: Static Verification (existing harness) ───────────────────────────
echo "Phase 1: Static Verification Harness"
echo "-------------------------------------"
if [ -x "./run_tests.sh" ]; then
    if ./run_tests.sh; then
        log_pass "Static verification harness"
    else
        log_fail "Static verification harness"
    fi
else
    log_skip "run_tests.sh not found or not executable"
fi
echo

# ─── Phase 2: File Presence Checks ─────────────────────────────────────────────
echo "Phase 2: E2E Test File Presence"
echo "-------------------------------------"

e2e_test_files=(
    "tests/unit/test_e2e_crypto_primitives.cpp"
    "tests/unit/test_e2e_signal_protocol.cpp"
    "tests/unit/test_e2e_mls_protocol.cpp"
    "tests/unit/test_e2e_build_verification.cpp"
    "tests/unit/test_e2e_android_jni.cpp"
    "tests/unit/test_e2e_counterintelligence.cpp"
)

for f in "${e2e_test_files[@]}"; do
    if [ -f "$ROOT_DIR/$f" ]; then
        log_pass "E2E test file exists: $(basename $f)"
    else
        log_fail "E2E test file missing: $f"
    fi
done
echo

# ─── Phase 3: CMakeLists Wiring Check ──────────────────────────────────────────
echo "Phase 3: CMakeLists Test Wiring"
echo "-------------------------------------"

test_cmake="$ROOT_DIR/tests/unit/CMakeLists.txt"
if [ -f "$test_cmake" ]; then
    for test_name in \
        "test_e2e_crypto_primitives" \
        "test_e2e_signal_protocol" \
        "test_e2e_mls_protocol" \
        "test_e2e_build_verification" \
        "test_e2e_android_jni" \
        "test_e2e_counterintelligence"; do
        if grep -q "$test_name" "$test_cmake"; then
            log_pass "CMakeLists includes $test_name"
        else
            log_fail "CMakeLists missing $test_name"
        fi
    done
else
    log_fail "tests/unit/CMakeLists.txt not found"
fi
echo

# ─── Phase 4: Source File Verification ─────────────────────────────────────────
echo "Phase 4: Source File Verification"
echo "-------------------------------------"

required_sources=(
    # Desktop counterintelligence
    "Telegram/SourceFiles/counterintelligence/surveillance_detector.h"
    "Telegram/SourceFiles/counterintelligence/surveillance_detector.cpp"
    "Telegram/SourceFiles/counterintelligence/adaptive_countermeasures.h"
    "Telegram/SourceFiles/counterintelligence/adaptive_countermeasures.cpp"
    "Telegram/SourceFiles/counterintelligence/countermeasure_randomizer.h"
    "Telegram/SourceFiles/counterintelligence/universal_security_validator.h"
    "Telegram/SourceFiles/counterintelligence/counterintelligence_controller.h"
    "Telegram/SourceFiles/counterintelligence/counterintelligence_controller.cpp"
    "Telegram/SourceFiles/counterintelligence/counterintelligence_dashboard.h"
    "Telegram/SourceFiles/counterintelligence/counterintelligence_dashboard.cpp"
    # Desktop security
    "Telegram/SourceFiles/security/hardware_detector.h"
    "Telegram/SourceFiles/security/universal_threat_detector.h"
    "Telegram/SourceFiles/security/gna_acoustic_security.h"
    "Telegram/SourceFiles/security/gna_acoustic_security.cpp"
    # Desktop protocols
    "Telegram/SourceFiles/data/data_signal_protocol.h"
    "Telegram/SourceFiles/data/data_signal_protocol.cpp"
    "Telegram/SourceFiles/data/data_mls_protocol.h"
    "Telegram/SourceFiles/data/data_mls_protocol.cpp"
    "Telegram/SourceFiles/data/data_signal_transport.h"
    "Telegram/SourceFiles/data/data_group_encryption.h"
    "Telegram/SourceFiles/data/data_group_encryption.cpp"
    # Desktop settings
    "Telegram/SourceFiles/settings/settings_cryptogram.cpp"
    "Telegram/SourceFiles/settings/settings_cryptogram.h"
    # Android JNI
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/qt_shims.h"
    "telegram-android/TMessagesProj/jni/cryptogram/desktop_shims.h"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_signal_protocol.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_signal_protocol.h"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_mls_protocol.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_mls_protocol.h"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_group_encryption.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_group_encryption.h"
    # Android Kotlin
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/OPSECHelper.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/ThreatDetector.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MediaMetadataHelper.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java"
    # CI/CD
    ".github/workflows/linux-deb.yml"
    ".github/workflows/android-apk.yml"
    # Build scripts
    "build_linux.sh"
    "build_android.sh"
    "build_all.sh"
    "run_tests.sh"
    # Version
    "Telegram/build/version"
    "telegram-android/gradle.properties"
)

for src in "${required_sources[@]}"; do
    if [ -f "$ROOT_DIR/$src" ]; then
        log_pass "Source exists: $(basename $src)"
        ((total_tests++))
    else
        log_fail "Source missing: $src"
    fi
done
echo

# ─── Phase 5: JNI Export Verification ──────────────────────────────────────────
echo "Phase 5: JNI Export Verification"
echo "-------------------------------------"

jni_wrapper="$ROOT_DIR/telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp"

jni_exports=(
    "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession"
    "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt"
    "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeDecrypt"
    "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetState"
    "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCreateGroup"
    "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeEncryptGroupMessage"
    "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeDecryptGroupMessage"
    "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeAddMember"
    "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeRemoveMember"
    "Java_org_telegram_messenger_cryptogram_EnhancedPrivacy_nativeIsCryptogramUser"
    "Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckDoubleRatchet"
    "Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckMLS"
    "Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeWrapDpiEvasion"
    "Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeSecureWipe"
    "Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeCheckPQC"
)

for export in "${jni_exports[@]}"; do
    if grep -q "$export" "$jni_wrapper" 2>/dev/null; then
        log_pass "JNI export: ${export##*_}"
    else
        log_fail "JNI export missing: $export"
    fi
done
echo

# ─── Phase 6: CMakeLists Source Wiring ─────────────────────────────────────────
echo "Phase 6: Desktop CMakeLists Source Wiring"
echo "-------------------------------------"

desktop_cmake="$ROOT_DIR/Telegram/CMakeLists.txt"

cmake_sources=(
    "surveillance_detector.cpp"
    "adaptive_countermeasures.cpp"
    "counterintelligence_controller.cpp"
    "counterintelligence_dashboard.cpp"
    "data_signal_protocol.cpp"
    "data_mls_protocol.cpp"
    "data_signal_transport.cpp"
    "data_group_encryption.cpp"
    "gna_acoustic_security.cpp"
)

for src in "${cmake_sources[@]}"; do
    if grep -q "$src" "$desktop_cmake" 2>/dev/null; then
        log_pass "CMakeLists wired: $src"
    else
        log_fail "CMakeLists missing: $src"
    fi
done
echo

# ─── Phase 7: Integration Hook Verification ────────────────────────────────────
echo "Phase 7: Android Integration Hooks"
echo "-------------------------------------"

integration_checks=(
    "encryptOutgoingMessage:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java"
    "decryptIncomingMessage:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java"
    "CryptogramSettingsActivity:telegram-android/TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java"
    "toggleCryptogramDoubleRatchet:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "toggleCryptogramMLS:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "toggleCryptogramPanicPassword:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "toggleCryptogramAntiForensics:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "toggleCryptogramDpiEvasion:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "toggleCryptogramStylometryShield:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "toggleCryptogramUtd:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "setCryptogramQuantumSecurityLevel:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "setCryptogramThreatDefenseLevel:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
    "OPSECHelper:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java"
    "ThreatDetector:telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java"
)

for check in "${integration_checks[@]}"; do
    pattern="${check%%:*}"
    filepath="${check##*:}"
    if grep -q "$pattern" "$ROOT_DIR/$filepath" 2>/dev/null; then
        log_pass "Integration hook: $pattern"
    else
        log_fail "Integration hook missing: $pattern in $(basename $filepath)"
    fi
done
echo

# ─── Phase 8: CI/CD Workflow Verification ──────────────────────────────────────
echo "Phase 8: CI/CD Workflow Verification"
echo "-------------------------------------"

workflow_checks=(
    "build_linux.sh:.github/workflows/linux-deb.yml"
    "dpkg-deb:.github/workflows/linux-deb.yml"
    "upload-artifact:.github/workflows/linux-deb.yml"
    "softprops/action-gh-release:.github/workflows/linux-deb.yml"
    "assembleAfatDebug:.github/workflows/android-apk.yml"
    "assembleAfatRelease:.github/workflows/android-apk.yml"
    "KEYSTORE_BASE64:.github/workflows/android-apk.yml"
    "upload-artifact:.github/workflows/android-apk.yml"
    "softprops/action-gh-release:.github/workflows/android-apk.yml"
)

for check in "${workflow_checks[@]}"; do
    pattern="${check%%:*}"
    filepath="${check##*:}"
    if grep -q "$pattern" "$ROOT_DIR/$filepath" 2>/dev/null; then
        log_pass "Workflow check: $pattern in $(basename $filepath)"
    else
        log_fail "Workflow check failed: $pattern in $(basename $filepath)"
    fi
done
echo

# ─── Phase 9: Qt Compatibility Verification ────────────────────────────────────
echo "Phase 9: Qt Compatibility (QT_NO_KEYWORDS)"
echo "-------------------------------------"

qt_checks=(
    "Q_SIGNALS:Telegram/SourceFiles/counterintelligence/countermeasure_randomizer.h"
    "Q_SIGNALS:Telegram/SourceFiles/counterintelligence/universal_security_validator.h"
    "QtCore/QObject:Telegram/SourceFiles/counterintelligence/countermeasure_randomizer.h"
    "QtCore/QObject:Telegram/SourceFiles/counterintelligence/universal_security_validator.h"
    "__has_include:Telegram/SourceFiles/counterintelligence/surveillance_detector.h"
    "__has_include:Telegram/SourceFiles/security/gna_acoustic_security.h"
)

for check in "${qt_checks[@]}"; do
    pattern="${check%%:*}"
    filepath="${check##*:}"
    if grep -q "$pattern" "$ROOT_DIR/$filepath" 2>/dev/null; then
        log_pass "Qt compat: $pattern in $(basename $filepath)"
    else
        log_fail "Qt compat failed: $pattern in $(basename $filepath)"
    fi
done
echo

# ─── Phase 10: Version Consistency ─────────────────────────────────────────────
echo "Phase 10: Version Consistency"
echo "-------------------------------------"

if grep -q "AppVersion" "$ROOT_DIR/Telegram/build/version" 2>/dev/null; then
    log_pass "Desktop version file has AppVersion"
else
    log_fail "Desktop version file missing AppVersion"
fi

if grep -q "APP_VERSION_CODE" "$ROOT_DIR/telegram-android/gradle.properties" 2>/dev/null; then
    log_pass "Android gradle.properties has APP_VERSION_CODE"
else
    log_fail "Android gradle.properties missing APP_VERSION_CODE"
fi

if grep -q "APP_VERSION_NAME" "$ROOT_DIR/telegram-android/gradle.properties" 2>/dev/null; then
    log_pass "Android gradle.properties has APP_VERSION_NAME"
else
    log_fail "Android gradle.properties missing APP_VERSION_NAME"
fi
echo

# ─── Phase 11: Android Native Library Structure ───────────────────────────────
echo "Phase 11: Android Native Library Structure"
echo "-------------------------------------"

native_dirs=(
    "telegram-android/TMessagesProj/jni/cryptogram/core"
    "telegram-android/TMessagesProj/jni/cryptogram/data"
    "telegram-android/TMessagesProj/jni/cryptogram/base"
)

for dir in "${native_dirs[@]}"; do
    if [ -d "$ROOT_DIR/$dir" ]; then
        log_pass "Native dir exists: $(basename $dir)"
    else
        log_fail "Native dir missing: $dir"
    fi
done

# Check JNI CMakeLists
if grep -q "add_library(cryptogram SHARED" "$ROOT_DIR/telegram-android/TMessagesProj/jni/CMakeLists.txt" 2>/dev/null; then
    log_pass "JNI CMakeLists declares cryptogram shared library"
else
    log_fail "JNI CMakeLists missing cryptogram library declaration"
fi

if grep -q "target_link_libraries(cryptogram" "$ROOT_DIR/telegram-android/TMessagesProj/jni/CMakeLists.txt" 2>/dev/null; then
    log_pass "JNI CMakeLists links cryptogram library"
else
    log_fail "JNI CMakeLists missing cryptogram link target"
fi
echo

# ─── Phase 12: Keystore Verification ───────────────────────────────────────────
echo "Phase 12: Signing Infrastructure"
echo "-------------------------------------"

if [ -f "$ROOT_DIR/telegram-android/cryptogram.keystore" ]; then
    log_pass "Local keystore exists for local release builds"
else
    log_skip "Local keystore not found (CI uses GitHub secrets)"
fi

if grep -q "cryptogram.keystore" "$ROOT_DIR/.gitignore" 2>/dev/null; then
    log_pass "Keystore is gitignored"
else
    log_fail "Keystore not in .gitignore"
fi
echo

# ─── Summary ───────────────────────────────────────────────────────────────────
echo "======================================"
echo "E2E Test Battery Summary"
echo "======================================"
echo "Passed:    $pass_count"
echo "Failed:    $fail_count"
echo "Skipped:   $skip_count"
echo "Total checks: $((pass_count + fail_count + skip_count))"
echo

if [ "$fail_count" -eq 0 ]; then
    echo "VERDICT: PASS"
    echo "All E2E verification checks passed."
    echo "Note: This harness verifies source wiring, build configuration, and"
    echo "integration hooks. Runtime crypto tests require compiled Catch2 binaries."
    exit 0
else
    echo "VERDICT: FAIL"
    echo "$fail_count check(s) failed. Review output above."
    exit 1
fi
