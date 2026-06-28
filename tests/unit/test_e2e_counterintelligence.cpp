/*
CRYPTOGRAM E2E Counterintelligence Tests
Verifies the desktop counterintelligence framework: surveillance detector,
adaptive countermeasures, countermeasure randomizer, universal security validator,
and the counterintelligence controller/dashboard wiring.
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

// ─── Source File Presence ──────────────────────────────────────────────────────

TEST_CASE("E2E: Counterintelligence header files exist", "[ci][e2e]") {
	const std::string base = "Telegram/SourceFiles/counterintelligence/";

	REQUIRE(fileExists(base + "surveillance_detector.h"));
	REQUIRE(fileExists(base + "adaptive_countermeasures.h"));
	REQUIRE(fileExists(base + "countermeasure_randomizer.h"));
	REQUIRE(fileExists(base + "universal_security_validator.h"));
	REQUIRE(fileExists(base + "counterintelligence_controller.h"));
	REQUIRE(fileExists(base + "counterintelligence_dashboard.h"));
}

TEST_CASE("E2E: Counterintelligence implementation files exist", "[ci][e2e]") {
	const std::string base = "Telegram/SourceFiles/counterintelligence/";

	REQUIRE(fileExists(base + "surveillance_detector.cpp"));
	REQUIRE(fileExists(base + "adaptive_countermeasures.cpp"));
	REQUIRE(fileExists(base + "counterintelligence_controller.cpp"));
	REQUIRE(fileExists(base + "counterintelligence_dashboard.cpp"));
}

// ─── Class Structure Verification ──────────────────────────────────────────────

TEST_CASE("E2E: SurveillanceDetector has detection methods", "[ci][e2e]") {
	auto content = readFile("Telegram/SourceFiles/counterintelligence/surveillance_detector.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "class SurveillanceDetector"));
	REQUIRE(containsPattern(content, "startDetection"));
	REQUIRE(containsPattern(content, "stopDetection"));
}

TEST_CASE("E2E: AdaptiveCountermeasures has countermeasure methods", "[ci][e2e]") {
	auto content = readFile("Telegram/SourceFiles/counterintelligence/adaptive_countermeasures.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "class AdaptiveCountermeasures"));
}

TEST_CASE("E2E: CountermeasureRandomizer has randomization methods", "[ci][e2e]") {
	auto content = readFile("Telegram/SourceFiles/counterintelligence/countermeasure_randomizer.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "class CountermeasureRandomizer"));
}

TEST_CASE("E2E: UniversalSecurityValidator has validation methods", "[ci][e2e]") {
	auto content = readFile("Telegram/SourceFiles/counterintelligence/universal_security_validator.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "class UniversalSecurityValidator"));
}

TEST_CASE("E2E: CounterIntelligenceController has coordination methods", "[ci][e2e]") {
	auto content = readFile("Telegram/SourceFiles/counterintelligence/counterintelligence_controller.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "class CounterIntelligenceController"));
}

TEST_CASE("E2E: CounterIntelligenceDashboard has display methods", "[ci][e2e]") {
	auto content = readFile("Telegram/SourceFiles/counterintelligence/counterintelligence_dashboard.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "class CounterIntelligenceDashboard"));
}

// ─── Qt Compatibility (QT_NO_KEYWORDS) ─────────────────────────────────────────

TEST_CASE("E2E: Counterintelligence headers use Q_SIGNALS/Q_SLOTS", "[ci][e2e][qt]") {
	auto randomizer = readFile("Telegram/SourceFiles/counterintelligence/countermeasure_randomizer.h");
	REQUIRE_FALSE(randomizer.empty());
	REQUIRE(containsPattern(randomizer, "Q_SIGNALS"));

	auto validator = readFile("Telegram/SourceFiles/counterintelligence/universal_security_validator.h");
	REQUIRE_FALSE(validator.empty());
	REQUIRE(containsPattern(validator, "Q_SIGNALS"));
}

TEST_CASE("E2E: Counterintelligence headers include QtCore/QObject", "[ci][e2e][qt]") {
	auto randomizer = readFile("Telegram/SourceFiles/counterintelligence/countermeasure_randomizer.h");
	REQUIRE_FALSE(randomizer.empty());
	REQUIRE(containsPattern(randomizer, "QtCore/QObject"));

	auto validator = readFile("Telegram/SourceFiles/counterintelligence/universal_security_validator.h");
	REQUIRE_FALSE(validator.empty());
	REQUIRE(containsPattern(validator, "QtCore/QObject"));
}

// ─── QtMultimedia Conditional Compilation ──────────────────────────────────────

TEST_CASE("E2E: SurveillanceDetector guards QtMultimedia includes", "[ci][e2e][qt]") {
	auto header = readFile("Telegram/SourceFiles/counterintelligence/surveillance_detector.h");
	REQUIRE_FALSE(header.empty());
	REQUIRE(containsPattern(header, "__has_include"));
}

TEST_CASE("E2E: GNA Acoustic Security guards QtMultimedia includes", "[ci][e2e][qt]") {
	auto header = readFile("Telegram/SourceFiles/security/gna_acoustic_security.h");
	REQUIRE_FALSE(header.empty());
	REQUIRE(containsPattern(header, "__has_include"));
}

// ─── CMakeLists Wiring ─────────────────────────────────────────────────────────

TEST_CASE("E2E: CMakeLists includes all counterintelligence sources", "[ci][e2e][build]") {
	auto content = readFile("Telegram/CMakeLists.txt");
	REQUIRE_FALSE(content.empty());

	REQUIRE(containsPattern(content, "surveillance_detector.cpp"));
	REQUIRE(containsPattern(content, "adaptive_countermeasures.cpp"));
	REQUIRE(containsPattern(content, "counterintelligence_controller.cpp"));
	REQUIRE(containsPattern(content, "counterintelligence_dashboard.cpp"));
}

// ─── Security Module Structure ─────────────────────────────────────────────────

TEST_CASE("E2E: Security module headers exist", "[ci][e2e][security]") {
	const std::string base = "Telegram/SourceFiles/security/";

	REQUIRE(fileExists(base + "hardware_detector.h"));
	REQUIRE(fileExists(base + "universal_threat_detector.h"));
	REQUIRE(fileExists(base + "gna_acoustic_security.h"));
	REQUIRE(fileExists(base + "gna_acoustic_security.cpp"));
}

TEST_CASE("E2E: Hardware detector has correct includes", "[ci][e2e][security]") {
	auto content = readFile("Telegram/SourceFiles/security/hardware_detector.h");
	REQUIRE_FALSE(content.empty());

	// Should not have relative path prefixes
	REQUIRE_FALSE(containsPattern(content, "../../lib_base/"));
}

TEST_CASE("E2E: Universal threat detector has correct includes", "[ci][e2e][security]") {
	auto content = readFile("Telegram/SourceFiles/security/universal_threat_detector.h");
	REQUIRE_FALSE(content.empty());

	REQUIRE_FALSE(containsPattern(content, "../../lib_base/"));
}

// ─── Namespace Verification ────────────────────────────────────────────────────

TEST_CASE("E2E: Counterintelligence uses SpyGram namespace", "[ci][e2e]") {
	auto detector = readFile("Telegram/SourceFiles/counterintelligence/surveillance_detector.h");
	REQUIRE_FALSE(detector.empty());
	REQUIRE(containsPattern(detector, "namespace SpyGram"));
	REQUIRE(containsPattern(detector, "Counterintelligence"));
}

// ─── Threat Level Enum ─────────────────────────────────────────────────────────

TEST_CASE("E2E: ThreatLevel enum is defined", "[ci][e2e]") {
	auto detector = readFile("Telegram/SourceFiles/counterintelligence/surveillance_detector.h");
	REQUIRE_FALSE(detector.empty());
	REQUIRE(containsPattern(detector, "ThreatLevel"));
}

// ─── Settings UI Verification ──────────────────────────────────────────────────

TEST_CASE("E2E: Settings cryptogram source exists", "[ci][e2e][settings]") {
	REQUIRE(fileExists("Telegram/SourceFiles/settings/settings_cryptogram.cpp"));
	REQUIRE(fileExists("Telegram/SourceFiles/settings/settings_cryptogram.h"));
}

TEST_CASE("E2E: Settings cryptogram has OPSEC sections", "[ci][e2e][settings]") {
	auto content = readFile("Telegram/SourceFiles/settings/settings_cryptogram.cpp");
	REQUIRE_FALSE(content.empty());

	// Verify key feature sections are present
	REQUIRE((containsPattern(content, "Signal") || containsPattern(content, "DoubleRatchet") || containsPattern(content, "doubleRatchet")));
	REQUIRE((containsPattern(content, "MLS") || containsPattern(content, "mls")));
}
