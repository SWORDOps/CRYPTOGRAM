#!/bin/bash

echo "======================================"
echo "CRYPTOGRAM Android - Test Battery"
echo "======================================"
echo ""

# Test 1: File Existence
echo "TEST 1: File Existence Verification"
echo "-------------------------------------"

files=(
    "TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp"
    "TMessagesProj/jni/cryptogram/data_signal_protocol.cpp"
    "TMessagesProj/jni/cryptogram/data_signal_protocol.h"
    "TMessagesProj/jni/cryptogram/data_mls_protocol.cpp"
    "TMessagesProj/jni/cryptogram/data_mls_protocol.h"
    "TMessagesProj/jni/cryptogram/data_group_encryption.cpp"
    "TMessagesProj/jni/cryptogram/data_group_encryption.h"
    "TMessagesProj/jni/cryptogram/data_enhanced_privacy.cpp"
    "TMessagesProj/jni/cryptogram/data_enhanced_privacy.h"
    "TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt"
    "TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.kt"
    "TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.kt"
    "TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.kt"
    "TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java"
    "TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java"
    "TMessagesProj/src/main/java/org/telegram/ui/Components/CryptogramIndicator.java"
)

pass=0
fail=0

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
        ((pass++))
    else
        echo "❌ MISSING: $file"
        ((fail++))
    fi
done

echo ""
echo "Files: $pass passed, $fail failed"
echo ""

# Test 2: Code Structure
echo "TEST 2: Code Structure Analysis"
echo "-------------------------------------"

# Check JNI wrapper has required methods
if grep -q "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession" TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp; then
    echo "✅ JNI: DoubleRatchet initializeSession method found"
else
    echo "❌ JNI: DoubleRatchet initializeSession method missing"
fi

if grep -q "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt" TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp; then
    echo "✅ JNI: DoubleRatchet encrypt method found"
else
    echo "❌ JNI: DoubleRatchet encrypt method missing"
fi

if grep -q "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCreateGroup" TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp; then
    echo "✅ JNI: MLSProtocol createGroup method found"
else
    echo "❌ JNI: MLSProtocol createGroup method missing"
fi

echo ""

# Test 3: Build System
echo "TEST 3: Build System Verification"
echo "-------------------------------------"

if grep -q "add_library(cryptogram STATIC" TMessagesProj/jni/CMakeLists.txt; then
    echo "✅ CMake: cryptogram library defined"
else
    echo "❌ CMake: cryptogram library not defined"
fi

if grep -q "target_link_libraries.*cryptogram" TMessagesProj/jni/CMakeLists.txt; then
    echo "✅ CMake: cryptogram library linked"
else
    echo "❌ CMake: cryptogram library not linked"
fi

echo ""

# Test 4: Integration Points
echo "TEST 4: Integration Point Verification"
echo "-------------------------------------"

if grep -q "CryptogramMessageHelper.encryptOutgoingMessage" TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java; then
    echo "✅ Integration: Outgoing encryption hooked"
else
    echo "❌ Integration: Outgoing encryption NOT hooked"
fi

if grep -q "CryptogramMessageHelper.decryptIncomingMessage" TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java; then
    echo "✅ Integration: Incoming decryption hooked"
else
    echo "❌ Integration: Incoming decryption NOT hooked"
fi

if grep -q "cryptogramDoubleRatchetEnabled" TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java; then
    echo "✅ Settings: Double Ratchet setting exists"
else
    echo "❌ Settings: Double Ratchet setting missing"
fi

if grep -q "CryptogramSettingsActivity" TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java; then
    echo "✅ UI: Settings menu entry exists"
else
    echo "❌ UI: Settings menu entry missing"
fi

echo ""

# Test 5: Line Counts
echo "TEST 5: Code Volume Analysis"
echo "-------------------------------------"

cpp_lines=$(find TMessagesProj/jni/cryptogram -name "*.cpp" -exec wc -l {} + | tail -1 | awk '{print $1}')
h_lines=$(find TMessagesProj/jni/cryptogram -name "*.h" -exec wc -l {} + | tail -1 | awk '{print $1}')
kt_lines=$(find TMessagesProj/src/main/java/org/telegram/messenger/cryptogram -name "*.kt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
java_lines=$(find TMessagesProj/src/main/java/org/telegram -name "Cryptogram*.java" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')

echo "C++ implementation: $cpp_lines lines"
echo "C++ headers: $h_lines lines"
echo "Kotlin API: $kt_lines lines"
echo "Java helpers: $java_lines lines"

total=$((cpp_lines + h_lines + kt_lines + java_lines))
echo "Total code: $total lines"

echo ""
echo "======================================"
echo "Test Battery Complete"
echo "======================================"
