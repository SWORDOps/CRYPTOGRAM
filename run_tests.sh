#!/usr/bin/env bash

set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass_count=0
fail_count=0
warn_count=0

log_pass() {
    printf '[PASS] %s\n' "$1"
    ((pass_count++))
}

log_fail() {
    printf '[FAIL] %s\n' "$1"
    ((fail_count++))
}

log_warn() {
    printf '[WARN] %s\n' "$1"
    ((warn_count++))
}

require_file() {
    local rel_path="$1"
    local label="${2:-$1}"
    if [ -f "$ROOT_DIR/$rel_path" ]; then
        log_pass "$label"
    else
        log_fail "$label (missing: $rel_path)"
    fi
}

require_grep() {
    local pattern="$1"
    local rel_path="$2"
    local label="$3"
    if grep -Eq "$pattern" "$ROOT_DIR/$rel_path"; then
        log_pass "$label"
    else
        log_fail "$label (missing pattern: $pattern)"
    fi
}

warn_grep() {
    local pattern="$1"
    local rel_path="$2"
    local label="$3"
    if grep -Eq "$pattern" "$ROOT_DIR/$rel_path"; then
        log_warn "$label"
    else
        log_pass "$label"
    fi
}

echo "======================================"
echo "CRYPTOGRAM Verification Harness"
echo "Static checks only: source wiring, API surface, and test assets"
echo "See: docs/status/TEST_HARNESS_SCOPE.md"
echo "======================================"
echo

echo "TEST 1: Required files"
echo "-------------------------------------"
required_files=(
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_signal_protocol.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_signal_protocol.h"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_mls_protocol.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_mls_protocol.h"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_group_encryption.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_group_encryption.h"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_enhanced_privacy.cpp"
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_enhanced_privacy.h"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.kt"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java"
    "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/Components/CryptogramIndicator.java"
    "tests/unit/test_cryptogram_features.cpp"
    "tests/unit/test_double_ratchet.cpp"
    "tests/unit/test_mls_protocol.cpp"
    "tests/unit/CMakeLists.txt"
    "telegram-android/TMessagesProj/jni/CMakeLists.txt"
    "docs/status/TEST_HARNESS_SCOPE.md"
)

for rel_path in "${required_files[@]}"; do
    require_file "$rel_path"
done

echo
echo "TEST 2: JNI and API surface"
echo "-------------------------------------"
require_grep 'Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI DoubleRatchet initializeSession exists"
require_grep 'Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI DoubleRatchet encrypt exists"
require_grep 'Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeDecrypt' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI DoubleRatchet decrypt exists"
require_grep 'Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetState' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI DoubleRatchet getState exists"
require_grep 'Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCreateGroup' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI MLS createGroup exists"
require_grep 'Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeEncryptGroupMessage' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI MLS encryptGroupMessage exists"
require_grep 'Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeDecryptGroupMessage' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI MLS decryptGroupMessage exists"
require_grep 'Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeAddMember' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI MLS addMember exists"
require_grep 'Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeRemoveMember' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI MLS removeMember exists"
require_grep 'Java_org_telegram_messenger_cryptogram_EnhancedPrivacy_nativeIsCryptogramUser' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI EnhancedPrivacy isCryptogramUser exists"
require_grep 'Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckDoubleRatchet' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI native Double Ratchet self-check exists"
require_grep 'Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckMLS' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI native MLS self-check exists"
require_grep 'System\.loadLibrary\("cryptogram"\)' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt" \
    "Kotlin native library load present"
require_grep 'nativeCheckDoubleRatchet' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt" \
    "Kotlin Double Ratchet self-check binding present"
require_grep 'nativeCheckMLS' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt" \
    "Kotlin MLS self-check binding present"
require_grep 'System\.loadLibrary\("cryptogram"\)' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.kt" \
    "DoubleRatchet native coupling present"
require_grep 'System\.loadLibrary\("cryptogram"\)' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.kt" \
    "MLS native coupling present"
require_grep 'nativeIsCryptogramUser' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.kt" \
    "EnhancedPrivacy native binding present"

echo
echo "TEST 3: Integration hooks"
echo "-------------------------------------"
require_grep 'encryptOutgoingMessage\(' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java" \
    "Outgoing encryption hook present"
require_grep 'decryptIncomingMessage\(' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java" \
    "Incoming decryption hook present"
require_grep 'CryptogramSettingsActivity' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java" \
    "Settings entry point present"
require_grep 'toggleCryptogramDoubleRatchet' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Double Ratchet toggle present"
require_grep 'toggleCryptogramMLS' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "MLS toggle present"
require_grep 'toggleCryptogramHideOnlineStatus' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Hide online status toggle present"
require_grep 'toggleCryptogramHideTypingIndicator' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Hide typing indicator toggle present"
require_grep 'toggleCryptogramHideReadReceipts' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Hide read receipts toggle present"
require_grep 'toggleCryptogramCuratedStickers' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Curated stickers toggle present"

echo
echo "TEST 3b: OPSEC integration hooks"
echo "-------------------------------------"
require_grep 'Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeWrapDpiEvasion' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI OPSECHelper DPI evasion exists"
require_grep 'Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeSecureWipe' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI OPSECHelper secure wipe exists"
require_grep 'Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeCheckPQC' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI OPSECHelper PQC check exists"
require_grep 'nativeWrapDpiEvasion' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/OPSECHelper.kt" \
    "Kotlin OPSECHelper DPI evasion binding present"
require_grep 'isStylometryShieldEnabled' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/OPSECHelper.kt" \
    "OPSECHelper stylometry shield check present"
require_grep 'applyStylometry' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/OPSECHelper.kt" \
    "OPSECHelper applyStylometry present"
require_grep 'OPSECHelper' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java" \
    "OPSECHelper wired into message pipeline"
require_grep 'ThreatDetector' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java" \
    "ThreatDetector wired into incoming message path"
require_file "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/ThreatDetector.kt" \
    "ThreatDetector.kt exists"
require_file "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MediaMetadataHelper.kt" \
    "MediaMetadataHelper.kt exists"
require_grep 'toggleCryptogramPanicPassword' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Panic password toggle present"
require_grep 'toggleCryptogramAntiForensics' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Anti-forensics toggle present"
require_grep 'toggleCryptogramDpiEvasion' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "DPI evasion toggle present"
require_grep 'toggleCryptogramStylometryShield' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Stylometry shield toggle present"
require_grep 'toggleCryptogramUtd' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "UTD toggle present"
require_grep 'setCryptogramQuantumSecurityLevel' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Quantum security level setter present"
require_grep 'setCryptogramThreatDefenseLevel' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java" \
    "Threat defense level setter present"
require_grep 'applyPreset' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java" \
    "OPSEC preset application present"
require_grep 'opsecSectionRow' \
    "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java" \
    "OPSEC section row present in settings UI"

echo
echo "TEST 4: Build declarations and test wiring"
echo "-------------------------------------"
require_grep 'add_library\(cryptogram SHARED' \
    "telegram-android/TMessagesProj/jni/CMakeLists.txt" \
    "cryptogram shared library declared"
require_grep 'target_link_libraries\(cryptogram' \
    "telegram-android/TMessagesProj/jni/CMakeLists.txt" \
    "cryptogram linked into JNI target"
require_grep 'test_cryptogram_features\.cpp' \
    "tests/unit/CMakeLists.txt" \
    "Feature unit test target wired"
require_grep 'test_double_ratchet\.cpp' \
    "tests/unit/CMakeLists.txt" \
    "Double Ratchet unit test target wired"
require_grep 'test_mls_protocol\.cpp' \
    "tests/unit/CMakeLists.txt" \
    "MLS protocol unit test target wired"
require_grep 'TEST_CASE\("MLS key packages are signed and verifiable"' \
    "tests/unit/test_mls_protocol.cpp" \
    "MLS key package test present"
require_grep 'TEST_CASE\("MLS basic group messaging works on supported ciphersuite"' \
    "tests/unit/test_mls_protocol.cpp" \
    "MLS group messaging test present"

echo
echo "TEST 5: Runtime gaps to review manually"
echo "-------------------------------------"
warn_grep 'Will call:' \
    "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
    "JNI wrapper still contains placeholder call paths"
warn_grep 'placeholder implementation|placeholder packages|placeholder group ID' \
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_mls_protocol.cpp" \
    "MLS implementation still contains placeholder logic"
warn_grep 'HPKE encryption would be used here|Current implementation passes the secret through until HPKE path encryption lands|return the secret \(placeholder\)' \
    "telegram-android/TMessagesProj/jni/cryptogram/data/data_mls_protocol.cpp" \
    "MLS dormant UpdatePath helper still contains non-HPKE placeholder path-secret handling"

echo
echo "Summary"
echo "-------------------------------------"
echo "Passed: $pass_count"
echo "Warnings: $warn_count"
echo "Failed: $fail_count"
echo
echo "Static harness verdict:"
if [ "$fail_count" -eq 0 ]; then
    echo "PASS"
    echo "This confirms the documented CRYPTOGRAM surface is wired into source and test assets."
    echo "It does not prove compilation, packaging, device runtime, or crypto correctness."
    exit 0
fi

echo "FAIL"
echo "Fix the failed static checks before relying on the runtime features."
exit 1
