#!/usr/bin/env bash

set -eu
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass_count=0
fail_count=0
warn_count=0

log_pass() {
    printf '[PASS] %s\n' "$1"
    pass_count=$((pass_count + 1))
}

log_fail() {
    printf '[FAIL] %s\n' "$1"
    fail_count=$((fail_count + 1))
}

log_warn() {
    printf '[WARN] %s\n' "$1"
    warn_count=$((warn_count + 1))
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

# Passes only when the pattern is ABSENT (guards against regressions like
# hardcoded personal paths).
forbid_grep() {
    local pattern="$1"
    local rel_path="$2"
    local label="$3"
    if grep -Eq "$pattern" "$ROOT_DIR/$rel_path"; then
        log_fail "$label (forbidden pattern found: $pattern)"
    else
        log_pass "$label"
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

# ---------------------------------------------------------------------------
# Static checks: file existence and pattern matching (original harness)
# ---------------------------------------------------------------------------
run_static_checks() {
    echo "======================================"
    echo "CRYPTOGRAM Verification Harness"
    echo "Static checks: source wiring, API surface, and test assets"
    echo "See: docs/status/TEST_HARNESS_SCOPE.md"
    echo "======================================"
    echo

    echo "TEST 1: Required files"
    echo "-------------------------------------"
    required_files=(
        "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/PanicPasswordHelper.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DpiEvasionHelper.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/StylometryShield.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/AntiForensicsHelper.java"
        "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java"
        "tests/unit/test_cryptogram_features.cpp"
        "tests/unit/test_double_ratchet.cpp"
        "tests/unit/test_mls_protocol.cpp"
        "tests/unit/test_e2e_quantum_kem.cpp"
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
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.java" \
        "Java native library load present"
    require_grep 'nativeCheckDoubleRatchet' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.java" \
        "Java Double Ratchet self-check binding present"
    require_grep 'nativeCheckMLS' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.java" \
        "Java MLS self-check binding present"
    require_grep 'CryptogramNative\.INSTANCE\.isLoaded\(\)' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.java" \
        "DoubleRatchet native coupling present"
    require_grep 'CryptogramNative\.INSTANCE\.isLoaded\(\)' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.java" \
        "MLS native coupling present"
    require_grep 'nativeIsCryptogramUser' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.java" \
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
    require_grep 'SettingsActivity' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java" \
        "Profile settings entry present"
    require_grep 'presentFragment\(new CryptogramSettingsActivity\(\)\)' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java" \
        "Cryptogram settings entry point present"
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
    require_grep 'zero-width|zero.width|0x200B' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DpiEvasionHelper.java" \
        "DPI evasion padding logic present"
    require_grep 'DoubleRatchet\.INSTANCE' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java" \
        "DoubleRatchet wired into message pipeline"
    require_grep 'MLSProtocol\.INSTANCE' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java" \
        "MLSProtocol wired into message pipeline"
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
    require_grep 'SharedConfig\.' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java" \
        "Settings activity wired to SharedConfig"
    require_grep 'stylometryRow' \
        "telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java" \
        "Stylometry section row present in settings UI"

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
    require_grep 'test_e2e_quantum_kem' \
        "tests/unit/CMakeLists.txt" \
        "QuantumGuard crypto test target wired"

    echo
    echo "TEST 5: Post-quantum layer, settings persistence, and AI opt-in"
    echo "-------------------------------------"
    require_grep 'SerializeCryptogramSettings|ApplyCryptogramSettings|kCryptogramSettingsMagic' \
        "Telegram/SourceFiles/core/core_settings.cpp" \
        "CRYPTOGRAM settings persistence trailer present"
    require_grep 'quantumWrapPayload|quantumUnwrapPayload' \
        "Telegram/SourceFiles/data/data_signal_protocol.cpp" \
        "Post-quantum message envelope wired"
    require_grep "bytes::type\('P'\), bytes::type\('Q'\), bytes::type\('E'\), bytes::type\('1'\)" \
        "Telegram/SourceFiles/data/data_signal_protocol.cpp" \
        "PQE1 envelope magic present"
    require_grep '0x02' \
        "Telegram/SourceFiles/data/data_signal_transport.cpp" \
        "Key-bundle PQ advertisement extension present"
    require_grep 'importPeerKemPublicKey|quantumEncapsulate|quantumDecapsulate|quantumVerify' \
        "Telegram/SourceFiles/data/data_quantumguard.cpp" \
        "QuantumGuard real crypto primitives present"
    require_grep 'performQuantumKEM|performClassicalX3DH' \
        "Telegram/SourceFiles/data/data_quantum_signal_impl.cpp" \
        "QuantumSignalProtocol primitives present"
    require_grep '_enabled = false' \
        "Telegram/SourceFiles/security/universal_threat_detector.cpp" \
        "AI threat detector opt-in default present"
    require_grep 'downloadAssetsAsync|QTcpServer' \
        "Telegram/SourceFiles/security/universal_threat_detector.cpp" \
        "On-demand AI assets and dynamic llama-server port present"
    require_grep 'UniversalThreatDetector::instance\(\)\.initialize\(\)' \
        "Telegram/SourceFiles/window/main_window.cpp" \
        "UTD startup initialization wired"
    forbid_grep 'VectorReVamp' \
        "Telegram/CMakeLists.txt" \
        "No personal build paths hardcoded in CMake"
    require_grep 'CRYPTOGRAM_ENABLE_COUNTERINTELLIGENCE' \
        "Telegram/CMakeLists.txt" \
        "Counterintelligence scaffolding gated behind build option (default OFF)"
    require_grep 'ifdef CRYPTOGRAM_COUNTERINTELLIGENCE' \
        "Telegram/SourceFiles/settings/settings_cryptogram.cpp" \
        "Surveillance settings section hidden when scaffolding compiled out"

    echo
    echo "TEST 6: Runtime gaps to review manually"
    echo "-------------------------------------"
    warn_grep 'Will call:' \
        "telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp" \
        "JNI wrapper still contains placeholder call paths"
    warn_grep 'Simple XOR|simple XOR|placeholder implementation|return the secret \(placeholder\)|HPKE encryption would be used here' \
        "Telegram/SourceFiles/data/data_mls_protocol.cpp" \
        "Desktop MLS still contains placeholder crypto paths"
    warn_grep 'RAND_bytes.*privateKey|RAND_bytes.*publicKey|placeholder.*signature|placeholder.*verification' \
        "Telegram/SourceFiles/data/data_mls_protocol.cpp" \
        "Desktop MLS still uses random bytes instead of real key generation"
    warn_grep 'TODO: Initialize PC/SC' \
        "Telegram/SourceFiles/data/data_cac_interface.cpp" \
        "CAC Linux backend still unimplemented (deprioritized: no test hardware)"
    warn_grep 'TODO\(quantum-transport\)' \
        "Telegram/SourceFiles/data/data_quantum_signal_impl.cpp" \
        "Quantum session-init transport still pending"
}

# ---------------------------------------------------------------------------
# Unit tests: compile and execute test binaries from build_tests/
# ---------------------------------------------------------------------------
run_unit_tests() {
    echo
    echo "======================================"
    echo "Unit Tests"
    echo "======================================"
    echo

    local build_dir="$ROOT_DIR/build_tests"

    if [ ! -d "$build_dir" ]; then
        echo "[INFO] build_tests/ directory not found."
        echo "       To build and run unit tests, configure with:"
        echo "         cmake -DCRYPTOGRAM_BUILD_TESTS=ON -B build_tests"
        echo "         cmake --build build_tests"
        echo "       Then re-run this script."
        echo
        return 0
    fi

    # Collect executable test binaries — skip CMake internals and non-executables.
    local test_binaries=()
    while IFS= read -r bin; do
        if [ -x "$bin" ] && file "$bin" | grep -q 'ELF.*executable'; then
            test_binaries+=("$bin")
        fi
    done < <(find "$build_dir" -maxdepth 1 -type f -executable 2>/dev/null | sort)

    if [ "${#test_binaries[@]}" -eq 0 ]; then
        echo "[INFO] No test binaries found in build_tests/."
        echo "       Build tests first with:"
        echo "         cmake -DCRYPTOGRAM_BUILD_TESTS=ON -B build_tests"
        echo "         cmake --build build_tests"
        echo
        return 0
    fi

    local ut_pass=0
    local ut_fail=0

    for bin in "${test_binaries[@]}"; do
        local name
        name="$(basename "$bin")"
        echo "-------------------------------------"
        echo "Running: $name"
        if "$bin" > "/tmp/${name}.out" 2>&1; then
            log_pass "Unit test: $name"
            ((ut_pass++))
        else
            log_fail "Unit test: $name (exit code $?)"
            cat "/tmp/${name}.out"
            ((ut_fail++))
        fi
    done

    echo
    echo "Unit test results: $ut_pass passed, $ut_fail failed"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
run_static_checks
run_unit_tests

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
