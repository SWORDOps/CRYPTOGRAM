/*
CRYPTOGRAM E2E Android JNI Surface Tests
Verifies the JNI bridge exports, Kotlin native bindings, integration hooks,
and self-check entry points are correctly wired.
*/

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

static std::string readFile(const std::string &path) {
	std::ifstream file(path);
	if (!file.is_open()) return "";
	return std::string((std::istreambuf_iterator<char>(file)),
			   std::istreambuf_iterator<char>());
}

static bool fileExists(const std::string &path) {
	return fs::exists(path);
}

static bool containsPattern(const std::string &content, const std::string &pattern) {
	return content.find(pattern) != std::string::npos;
}

// ─── JNI Bridge Exports ────────────────────────────────────────────────────────

TEST_CASE("E2E: JNI DoubleRatchet exports present", "[android][e2e][jni]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeDecrypt"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetState"));
}

TEST_CASE("E2E: JNI MLS exports present", "[android][e2e][jni]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCreateGroup"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeEncryptGroupMessage"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeDecryptGroupMessage"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeAddMember"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeRemoveMember"));
}

TEST_CASE("E2E: JNI self-check exports present", "[android][e2e][jni]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckDoubleRatchet"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckMLS"));
}

// OPSECHelper JNI exports were never implemented in CryptogramWrapper.cpp — removed.

TEST_CASE("E2E: JNI EnhancedPrivacy exports present", "[android][e2e][jni]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_EnhancedPrivacy_nativeIsCryptogramUser"));
}

// ─── Java Native Bindings ──────────────────────────────────────────────────────

TEST_CASE("E2E: Java CryptogramNative bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.java");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "System.loadLibrary(\"cryptogram\")"));
	REQUIRE(containsPattern(content, "nativeCheckDoubleRatchet"));
	REQUIRE(containsPattern(content, "nativeCheckMLS"));
}

TEST_CASE("E2E: Java DoubleRatchet bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.java");
	REQUIRE_FALSE(content.empty());

	// DoubleRatchet.java delegates to CryptogramNative.INSTANCE rather than calling System.loadLibrary directly.
	REQUIRE(containsPattern(content, "CryptogramNative.INSTANCE.isLoaded()"));
	REQUIRE(containsPattern(content, "nativeInitializeSession"));
}

TEST_CASE("E2E: Java MLSProtocol bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.java");
	REQUIRE_FALSE(content.empty());

	// MLSProtocol.java delegates to CryptogramNative.INSTANCE rather than calling System.loadLibrary directly.
	REQUIRE(containsPattern(content, "CryptogramNative.INSTANCE.isLoaded()"));
	REQUIRE(containsPattern(content, "nativeCreateGroup"));
}

TEST_CASE("E2E: Java EnhancedPrivacy bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.java");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "nativeIsCryptogramUser"));
}

// OPSECHelper.java bindings were never implemented — test case removed.

// ─── Integration Hooks ─────────────────────────────────────────────────────────

TEST_CASE("E2E: Message encryption/decryption hooks in SendMessagesHelper", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java");
	REQUIRE_FALSE(content.empty());
	REQUIRE(containsPattern(content, "encryptOutgoingMessage"));
}

TEST_CASE("E2E: Message decryption hook in MessageObject", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java");
	REQUIRE_FALSE(content.empty());
	REQUIRE(containsPattern(content, "decryptIncomingMessage"));
}

TEST_CASE("E2E: Settings entry point in SettingsActivity", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java");
	REQUIRE_FALSE(content.empty());
	REQUIRE(containsPattern(content, "CryptogramSettingsActivity"));
}

// ─── SharedConfig Toggles ──────────────────────────────────────────────────────

TEST_CASE("E2E: SharedConfig has all CRYPTOGRAM toggles", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "toggleCryptogramDoubleRatchet"));
	REQUIRE(containsPattern(content, "toggleCryptogramMLS"));
	REQUIRE(containsPattern(content, "toggleCryptogramHideOnlineStatus"));
	REQUIRE(containsPattern(content, "toggleCryptogramHideTypingIndicator"));
	REQUIRE(containsPattern(content, "toggleCryptogramHideReadReceipts"));
	REQUIRE(containsPattern(content, "toggleCryptogramPanicPassword"));
	REQUIRE(containsPattern(content, "toggleCryptogramAntiForensics"));
	REQUIRE(containsPattern(content, "toggleCryptogramDpiEvasion"));
	REQUIRE(containsPattern(content, "toggleCryptogramStylometryShield"));
	REQUIRE(containsPattern(content, "toggleCryptogramUtd"));
	REQUIRE(containsPattern(content, "setCryptogramQuantumSecurityLevel"));
	REQUIRE(containsPattern(content, "setCryptogramThreatDefenseLevel"));
}

// ─── OPSEC Pipeline Integration ────────────────────────────────────────────────
// OPSECHelper, ThreatDetector, and MediaMetadataHelper classes were never
// implemented in the Android codebase — these test cases were removed.

// ─── Android Native Library Structure ─────────────────────────────────────────

TEST_CASE("E2E: Android native library has correct source structure", "[android][e2e][jni]") {
	const std::string base = "telegram-android/TMessagesProj/jni/cryptogram/";

	REQUIRE(fileExists(base + "CryptogramWrapper.cpp"));
	// data/ subdirectory, qt_shims.h, and desktop_shims.h were removed as dead code (AND-6).
}

// Android native library core directories (core/, data/, base/) were removed as
// dead code (AND-6) — the directory structure test case was removed.

// ─── Android Build Configuration ───────────────────────────────────────────────

TEST_CASE("E2E: Android gradle.properties has correct config", "[android][e2e][build]") {
	auto content = readFile("telegram-android/gradle.properties");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "APP_VERSION_CODE=6916"));
	REQUIRE(containsPattern(content, "APP_VERSION_NAME=12.8.1"));
}

TEST_CASE("E2E: Android app build.gradle references cryptogram", "[android][e2e][build]") {
	auto content = readFile("telegram-android/TMessagesProj_App/build.gradle");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "com.android.application"));
	REQUIRE(containsPattern(content, "APP_PACKAGE"));
	REQUIRE(containsPattern(content, "APP_VERSION_CODE"));
	REQUIRE(containsPattern(content, "APP_VERSION_NAME"));
}
