#!/bin/bash

echo "======================================"
echo "CRYPTOGRAM - Syntax & API Validation"
echo "======================================"
echo ""

# Test Java/Kotlin syntax issues
echo "TEST 6: Import & Package Validation"
echo "-------------------------------------"

# Check Kotlin files have correct package
for file in telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/*.kt; do
    if grep -q "package org.telegram.messenger.cryptogram" "$file"; then
        echo "✅ $(basename $file): Correct package"
    else
        echo "❌ $(basename $file): Wrong package"
    fi
done

# Check Java helpers
if grep -q "package org.telegram.messenger.cryptogram" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java; then
    echo "✅ CryptogramMessageHelper.java: Correct package"
else
    echo "❌ CryptogramMessageHelper.java: Wrong package"
fi

if grep -q "package org.telegram.ui" telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java; then
    echo "✅ CryptogramSettingsActivity.java: Correct package"
else
    echo "❌ CryptogramSettingsActivity.java: Wrong package"
fi

echo ""

# Test API consistency
echo "TEST 7: API Method Consistency"
echo "-------------------------------------"

# Check DoubleRatchet.kt has all methods
methods=("initializeSession" "encrypt" "decrypt" "hasSession" "getState")
for method in "${methods[@]}"; do
    if grep -q "fun $method" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.kt; then
        echo "✅ DoubleRatchet.$method() exists"
    else
        echo "❌ DoubleRatchet.$method() missing"
    fi
done

# Check MLSProtocol.kt has all methods
mls_methods=("createGroup" "encryptGroupMessage" "decryptGroupMessage" "addMember" "removeMember")
for method in "${mls_methods[@]}"; do
    if grep -q "fun $method" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.kt; then
        echo "✅ MLSProtocol.$method() exists"
    else
        echo "❌ MLSProtocol.$method() missing"
    fi
done

echo ""

# Test Message Helper
echo "TEST 8: Message Flow Validation"
echo "-------------------------------------"

# Check encryption/decryption methods
if grep -q "public static String encryptOutgoingMessage" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java; then
    echo "✅ CryptogramMessageHelper.encryptOutgoingMessage() exists"
else
    echo "❌ CryptogramMessageHelper.encryptOutgoingMessage() missing"
fi

if grep -q "public static String decryptIncomingMessage" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java; then
    echo "✅ CryptogramMessageHelper.decryptIncomingMessage() exists"
else
    echo "❌ CryptogramMessageHelper.decryptIncomingMessage() missing"
fi

if grep -q "public static boolean isEncryptedMessage" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java; then
    echo "✅ CryptogramMessageHelper.isEncryptedMessage() exists"
else
    echo "❌ CryptogramMessageHelper.isEncryptedMessage() missing"
fi

echo ""

# Test Settings Integration
echo "TEST 9: Settings Storage Validation"
echo "-------------------------------------"

if grep -q "public static void toggleCryptogramDoubleRatchet()" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java; then
    echo "✅ SharedConfig.toggleCryptogramDoubleRatchet() exists"
else
    echo "❌ SharedConfig.toggleCryptogramDoubleRatchet() missing"
fi

if grep -q "public static void toggleCryptogramMLS()" telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java; then
    echo "✅ SharedConfig.toggleCryptogramMLS() exists"
else
    echo "❌ SharedConfig.toggleCryptogramMLS() missing"
fi

echo ""

# Test UI Components
echo "TEST 10: UI Component Validation"
echo "-------------------------------------"

if grep -q "class CryptogramSettingsActivity extends BaseFragment" telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java; then
    echo "✅ CryptogramSettingsActivity extends BaseFragment"
else
    echo "❌ CryptogramSettingsActivity does not extend BaseFragment"
fi

if grep -q "class CryptogramIndicator" telegram-android/TMessagesProj/src/main/java/org/telegram/ui/Components/CryptogramIndicator.java; then
    echo "✅ CryptogramIndicator class exists"
else
    echo "❌ CryptogramIndicator class missing"
fi

echo ""
echo "======================================"
echo "Syntax & API Validation Complete"
echo "======================================"
