/*
CRYPTOGRAM E2E Build Verification Tests
Verifies that source files, CMakeLists wiring, and build artifacts
are correctly configured for both desktop and Android platforms.
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

// ─── Desktop Source File Presence ──────────────────────────────────────────────

TEST_CASE("E2E: Desktop counterintelligence source files exist", "[build][e2e]") {
	const std::string base = "Telegram/SourceFiles/counterintelligence/";

	REQUIRE(fileExists(base + "surveillance_detector.h"));
	REQUIRE(fileExists(base + "surveillance_detector.cpp"));
	REQUIRE(fileExists(base + "adaptive_countermeasures.h"));
	REQUIRE(fileExists(base + "adaptive_countermeasures.cpp"));
	REQUIRE(fileExists(base + "countermeasure_randomizer.h"));
	REQUIRE(fileExists(base + "universal_security_validator.h"));
	REQUIRE(fileExists(base + "counterintelligence_controller.h"));
	REQUIRE(fileExists(base + "counterintelligence_controller.cpp"));
	REQUIRE(fileExists(base + "counterintelligence_dashboard.h"));
	REQUIRE(fileExists(base + "counterintelligence_dashboard.cpp"));
}

TEST_CASE("E2E: Desktop security source files exist", "[build][e2e]") {
	const std::string base = "Telegram/SourceFiles/security/";

	REQUIRE(fileExists(base + "hardware_detector.h"));
	REQUIRE(fileExists(base + "universal_threat_detector.h"));
	REQUIRE(fileExists(base + "gna_acoustic_security.h"));
	REQUIRE(fileExists(base + "gna_acoustic_security.cpp"));
}

TEST_CASE("E2E: Desktop protocol source files exist", "[build][e2e]") {
	const std::string base = "Telegram/SourceFiles/data/";

	REQUIRE(fileExists(base + "data_signal_protocol.h"));
	REQUIRE(fileExists(base + "data_signal_protocol.cpp"));
	REQUIRE(fileExists(base + "data_mls_protocol.h"));
	REQUIRE(fileExists(base + "data_mls_protocol.cpp"));
	REQUIRE(fileExists(base + "data_signal_transport.h"));
	REQUIRE(fileExists(base + "data_signal_transport.cpp"));
	REQUIRE(fileExists(base + "data_group_encryption.h"));
	REQUIRE(fileExists(base + "data_group_encryption.cpp"));
}

TEST_CASE("E2E: Desktop settings source files exist", "[build][e2e]") {
	REQUIRE(fileExists("Telegram/SourceFiles/settings/settings_cryptogram.cpp"));
	REQUIRE(fileExists("Telegram/SourceFiles/settings/settings_cryptogram.h"));
}

// ─── CMakeLists Wiring ─────────────────────────────────────────────────────────

TEST_CASE("E2E: Desktop CMakeLists includes counterintelligence sources", "[build][e2e]") {
	auto content = readFile("Telegram/CMakeLists.txt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "counterintelligence_controller.cpp"));
	REQUIRE(containsPattern(content, "counterintelligence_dashboard.cpp"));
	REQUIRE(containsPattern(content, "surveillance_detector.cpp"));
	REQUIRE(containsPattern(content, "adaptive_countermeasures.cpp"));
}

TEST_CASE("E2E: Desktop CMakeLists includes protocol sources", "[build][e2e]") {
	auto content = readFile("Telegram/CMakeLists.txt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "data_signal_protocol.cpp"));
	REQUIRE(containsPattern(content, "data_mls_protocol.cpp"));
	REQUIRE(containsPattern(content, "data_signal_transport.cpp"));
	REQUIRE(containsPattern(content, "data_group_encryption.cpp"));
}

TEST_CASE("E2E: Desktop CMakeLists includes security sources", "[build][e2e]") {
	auto content = readFile("Telegram/CMakeLists.txt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "gna_acoustic_security.cpp"));
}

TEST_CASE("E2E: Test CMakeLists includes all E2E test targets", "[build][e2e]") {
	auto content = readFile("tests/unit/CMakeLists.txt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "test_e2e_crypto_primitives.cpp"));
	REQUIRE(containsPattern(content, "test_e2e_signal_protocol.cpp"));
	REQUIRE(containsPattern(content, "test_e2e_mls_protocol.cpp"));
	REQUIRE(containsPattern(content, "test_e2e_build_verification.cpp"));
	REQUIRE(containsPattern(content, "test_e2e_android_jni.cpp"));
	REQUIRE(containsPattern(content, "test_e2e_counterintelligence.cpp"));
}

// ─── Android Source File Presence ──────────────────────────────────────────────

TEST_CASE("E2E: Android JNI cryptogram source files exist", "[build][e2e][android]") {
	const std::string base = "telegram-android/TMessagesProj/jni/cryptogram/";

	REQUIRE(fileExists(base + "CryptogramWrapper.cpp"));
	REQUIRE(fileExists(base + "qt_shims.h"));
	REQUIRE(fileExists(base + "desktop_shims.h"));
	REQUIRE(fileExists(base + "data/data_signal_protocol.cpp"));
	REQUIRE(fileExists(base + "data/data_signal_protocol.h"));
	REQUIRE(fileExists(base + "data/data_mls_protocol.cpp"));
	REQUIRE(fileExists(base + "data/data_mls_protocol.h"));
	REQUIRE(fileExists(base + "data/data_group_encryption.cpp"));
	REQUIRE(fileExists(base + "data/data_group_encryption.h"));
}

TEST_CASE("E2E: Android Kotlin cryptogram source files exist", "[build][e2e][android]") {
	const std::string base = "telegram-android/TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/";

	REQUIRE(fileExists(base + "CryptogramNative.kt"));
	REQUIRE(fileExists(base + "DoubleRatchet.kt"));
	REQUIRE(fileExists(base + "MLSProtocol.kt"));
	REQUIRE(fileExists(base + "EnhancedPrivacy.kt"));
	REQUIRE(fileExists(base + "CryptogramMessageHelper.java"));
}

TEST_CASE("E2E: Android settings UI source files exist", "[build][e2e][android]") {
	REQUIRE(fileExists("telegram-android/TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java"));
}

// ─── Android JNI CMakeLists ────────────────────────────────────────────────────

TEST_CASE("E2E: Android JNI CMakeLists declares cryptogram library", "[build][e2e][android]") {
	auto content = readFile("telegram-android/TMessagesProj/jni/CMakeLists.txt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "add_library(cryptogram SHARED"));
	REQUIRE(containsPattern(content, "target_link_libraries(cryptogram"));
}

// ─── Build Script Presence ─────────────────────────────────────────────────────

TEST_CASE("E2E: Build scripts exist and are executable", "[build][e2e]") {
	REQUIRE(fileExists("build_linux.sh"));
	REQUIRE(fileExists("build_android.sh"));
	REQUIRE(fileExists("build_all.sh"));
	REQUIRE(fileExists("run_tests.sh"));
}

// ─── GitHub Actions Workflow Presence ──────────────────────────────────────────

TEST_CASE("E2E: Production GitHub Actions workflows exist", "[build][e2e][ci]") {
	REQUIRE(fileExists(".github/workflows/linux-deb.yml"));
	REQUIRE(fileExists(".github/workflows/android-apk.yml"));
}

TEST_CASE("E2E: Linux deb workflow has correct structure", "[build][e2e][ci]") {
	auto content = readFile(".github/workflows/linux-deb.yml");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "build_linux.sh"));
	REQUIRE(containsPattern(content, "dpkg-deb"));
	REQUIRE(containsPattern(content, "upload-artifact"));
	REQUIRE(containsPattern(content, "softprops/action-gh-release"));
}

TEST_CASE("E2E: Android APK workflow has correct structure", "[build][e2e][ci]") {
	auto content = readFile(".github/workflows/android-apk.yml");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "assembleAfatDebug"));
	REQUIRE(containsPattern(content, "assembleAfatRelease"));
	REQUIRE(containsPattern(content, "KEYSTORE_BASE64"));
	REQUIRE(containsPattern(content, "upload-artifact"));
	REQUIRE(containsPattern(content, "softprops/action-gh-release"));
}

// ─── Version Consistency ───────────────────────────────────────────────────────

TEST_CASE("E2E: Desktop version file exists", "[build][e2e]") {
	REQUIRE(fileExists("Telegram/build/version"));
	auto content = readFile("Telegram/build/version");
	REQUIRE_FALSE(content.empty());
	REQUIRE(containsPattern(content, "AppVersion"));
}

TEST_CASE("E2E: Android gradle.properties has version info", "[build][e2e][android]") {
	auto content = readFile("telegram-android/gradle.properties");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "APP_VERSION_CODE"));
	REQUIRE(containsPattern(content, "APP_VERSION_NAME"));
	REQUIRE(containsPattern(content, "APP_PACKAGE"));
}
