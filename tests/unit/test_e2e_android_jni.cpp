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

TEST_CASE("E2E: JNI OPSECHelper exports present", "[android][e2e][jni]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeWrapDpiEvasion"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeSecureWipe"));
	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_OPSECHelper_nativeCheckPQC"));
}

TEST_CASE("E2E: JNI EnhancedPrivacy exports present", "[android][e2e][jni]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "Java_org_telegram_messenger_cryptogram_EnhancedPrivacy_nativeIsCryptogramUser"));
}

// ─── Kotlin Native Bindings ────────────────────────────────────────────────────

TEST_CASE("E2E: Kotlin CryptogramNative bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.kt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "System.loadLibrary(\"cryptogram\")"));
	REQUIRE(containsPattern(content, "nativeCheckDoubleRatchet"));
	REQUIRE(containsPattern(content, "nativeCheckMLS"));
}

TEST_CASE("E2E: Kotlin DoubleRatchet bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/DoubleRatchet.kt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "System.loadLibrary(\"cryptogram\")"));
}

TEST_CASE("E2E: Kotlin MLSProtocol bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MLSProtocol.kt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "System.loadLibrary(\"cryptogram\")"));
}

TEST_CASE("E2E: Kotlin EnhancedPrivacy bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/EnhancedPrivacy.kt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "nativeIsCryptogramUser"));
}

TEST_CASE("E2E: Kotlin OPSECHelper bindings present", "[android][e2e][kotlin]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/OPSECHelper.kt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "nativeWrapDpiEvasion"));
	REQUIRE(containsPattern(content, "isStylometryShieldEnabled"));
	REQUIRE(containsPattern(content, "applyStylometry"));
}

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

TEST_CASE("E2E: Settings entry point in ProfileActivity", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java");
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

TEST_CASE("E2E: OPSECHelper wired into message pipeline", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java");
	REQUIRE_FALSE(content.empty());
	REQUIRE(containsPattern(content, "OPSECHelper"));
}

TEST_CASE("E2E: ThreatDetector wired into incoming message path", "[android][e2e][integration]") {
	auto content = readFile("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramMessageHelper.java");
	REQUIRE_FALSE(content.empty());
	REQUIRE(containsPattern(content, "ThreatDetector"));
}

TEST_CASE("E2E: ThreatDetector.kt exists", "[android][e2e][integration]") {
	REQUIRE(fileExists("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/ThreatDetector.kt"));
}

TEST_CASE("E2E: MediaMetadataHelper.kt exists", "[android][e2e][integration]") {
	REQUIRE(fileExists("telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/MediaMetadataHelper.kt"));
}

// ─── Android Native Library Structure ─────────────────────────────────────────

TEST_CASE("E2E: Android native library has correct source structure", "[android][e2e][jni]") {
	const std::string base = "telegram-android/TMessagesProj/jni/cryptogram/";

	REQUIRE(fileExists(base + "CryptogramWrapper.cpp"));
	REQUIRE(fileExists(base + "data/data_signal_protocol.cpp"));
	REQUIRE(fileExists(base + "data/data_signal_protocol.h"));
	REQUIRE(fileExists(base + "data/data_mls_protocol.cpp"));
	REQUIRE(fileExists(base + "data/data_mls_protocol.h"));
	REQUIRE(fileExists(base + "data/data_group_encryption.cpp"));
	REQUIRE(fileExists(base + "data/data_group_encryption.h"));
	REQUIRE(fileExists(base + "qt_shims.h"));
	REQUIRE(fileExists(base + "desktop_shims.h"));
}

TEST_CASE("E2E: Android native library has core directories", "[android][e2e][jni]") {
	REQUIRE(fs::is_directory("telegram-android/TMessagesProj/jni/cryptogram/core"));
	REQUIRE(fs::is_directory("telegram-android/TMessagesProj/jni/cryptogram/data"));
	REQUIRE(fs::is_directory("telegram-android/TMessagesProj/jni/cryptogram/base"));
}

// ─── Android Build Configuration ───────────────────────────────────────────────

TEST_CASE("E2E: Android gradle.properties has correct config", "[android][e2e][build]") {
	auto content = readFile("telegram-android/gradle.properties");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "APP_VERSION_CODE=6666"));
	REQUIRE(containsPattern(content, "APP_VERSION_NAME=12.6.4"));
}

TEST_CASE("E2E: Android app build.gradle references cryptogram", "[android][e2e][build]") {
	auto content = readFile("telegram-android/TMessagesProj_App/build.gradle");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "com.android.application"));
	REQUIRE(containsPattern(content, "APP_PACKAGE"));
	REQUIRE(containsPattern(content, "APP_VERSION_CODE"));
	REQUIRE(containsPattern(content, "APP_VERSION_NAME"));
}
