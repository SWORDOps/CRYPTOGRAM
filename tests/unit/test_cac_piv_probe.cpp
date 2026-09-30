/*
 * CRYPTOGRAM — CAC/PIV hardware probe: FIPS YubiKey in PIV mode over PC/SC.
 *
 * Standalone host binary (like test_android_persistence_host.cpp): no Qt, no
 * Catch2 — just PC/SC Lite and OpenSSL. It drives the exact APDU sequence the
 * production Linux backend in
 * Telegram/SourceFiles/data/data_cac_interface.cpp implements:
 *
 *   1. SCardEstablishContext + SCardListReaders        (reader discovery)
 *   2. SCardGetStatusChange, bounded wait              (card presence)
 *   3. SELECT AID   00 A4 04 00 05 | A0 00 00 03 08    (PIV applet select)
 *   4. GET DATA     00 CB 3F FF 05 | 5C 03 5F C1 05 00 (X.509 cert, slot 9a)
 *   5. VERIFY PIN   00 20 00 80 08 | <PIN padded 8B>   (only when needed)
 *   6. GEN AUTH     00 87 07 9A    | 7C .. 81 .. <EM>   (RSA-2048 sign,
 *      algorithm 0x07 = RSA 2048, key ref 9A, PKCS#1 v1.5 / SHA-256)
 *   7. Verify the returned signature locally against the certificate's
 *      public key (OpenSSL EVP).
 *
 * Exit codes:
 *   0 — probe PASSED with a card, or SKIPPED cleanly (no reader / no card
 *       after the bounded wait: prints instructions and exits 0 so automated
 *       harnesses without hardware stay green).
 *   1 — a card was present but the probe FAILED.
 *
 * Manual run:
 *   ./build_tests/tests/unit/test_cac_piv_probe
 *   CAC_PROBE_PIN=123456 CAC_PROBE_WAIT_SECS=60 \
 *       ./build_tests/tests/unit/test_cac_piv_probe
 *
 * See docs/CAC_YUBIKEY_PROVISIONING.md for provisioning the YubiKey.
 */

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace {

int gChecks = 0;
int gFailures = 0;

#define CHECK(cond)                                                        \
	do {                                                                   \
		++gChecks;                                                         \
		if (!(cond)) {                                                     \
			++gFailures;                                                   \
			std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
		}                                                                  \
	} while (false)

void hexdump(const char *prefix, const std::vector<unsigned char> &data) {
	std::printf("    %s [%zu]:", prefix, data.size());
	const size_t shown = std::min<size_t>(data.size(), 16);
	for (size_t i = 0; i < shown; ++i) {
		std::printf(" %02X", data[i]);
	}
	if (data.size() > shown) {
		std::printf(" ...(%zu more)", data.size() - shown);
	}
	std::printf("\n");
}

// ---------- TLV -------------------------------------------------------------

struct Tlv {
	uint16_t tag = 0;
	std::vector<unsigned char> value;
};

std::vector<Tlv> parseTlvList(const std::vector<unsigned char> &buffer) {
	std::vector<Tlv> result;
	size_t i = 0;
	while (i + 2 <= buffer.size()) {
		uint16_t tag = buffer[i++];
		if ((tag & 0x1F) == 0x1F && i < buffer.size()) {
			tag = uint16_t((tag << 8) | buffer[i++]);
		}
		if (i >= buffer.size()) break;
		const unsigned char first = buffer[i++];
		size_t length = 0;
		if (first < 0x80) {
			length = first;
		} else if (first == 0x81 && i < buffer.size()) {
			length = buffer[i++];
		} else if (first == 0x82 && i + 1 < buffer.size()) {
			length = (size_t(buffer[i]) << 8) | buffer[i + 1];
			i += 2;
		} else {
			break;
		}
		if (i + length > buffer.size()) break;
		result.push_back({tag,
			std::vector<unsigned char>(buffer.begin() + long(i),
				buffer.begin() + long(i + length))});
		i += length;
	}
	return result;
}

const Tlv *findTlv(const std::vector<Tlv> &list, uint16_t tag) {
	for (const auto &tlv : list) {
		if (tlv.tag == tag) {
			return &tlv;
		}
	}
	return nullptr;
}

// ---------- PC/SC session ---------------------------------------------------

SCARDCONTEXT gContext = 0;
bool gContextValid = false;
SCARDHANDLE gCard = 0;
DWORD gProtocol = 0;
bool gCardValid = false;
unsigned char gSw1 = 0;
unsigned char gSw2 = 0;

std::string scError(LONG rc) {
	const char *text = pcsc_stringify_error(rc);
	return text ? std::string(text) : std::string("unknown");
}

bool establishContext() {
	if (gContextValid) return true;
	const LONG rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &gContext);
	if (rc != SCARD_S_SUCCESS) {
		std::printf("  [INFO] SCardEstablishContext failed: %s\n", scError(rc).c_str());
		return false;
	}
	gContextValid = true;
	return true;
}

std::vector<std::string> listReaders() {
	std::vector<std::string> names;
	if (!establishContext()) return names;
	DWORD length = 0;
	LONG rc = SCardListReaders(gContext, nullptr, nullptr, &length);
	if (rc != SCARD_S_SUCCESS || length == 0) {
		return names;
	}
	std::vector<char> buffer(length, '\0');
	rc = SCardListReaders(gContext, nullptr, buffer.data(), &length);
	if (rc != SCARD_S_SUCCESS) return names;
	for (const char *p = buffer.data(); *p != '\0'; p += std::strlen(p) + 1) {
		names.emplace_back(p);
	}
	return names;
}

bool readerHasCard(const std::string &name, std::string *atrOut = nullptr) {
	SCARD_READERSTATE state = {};
	state.szReader = name.c_str();
	state.dwCurrentState = SCARD_STATE_UNAWARE;
	if (SCardGetStatusChange(gContext, 0, &state, 1) != SCARD_S_SUCCESS) {
		return false;
	}
	if (atrOut && (state.dwEventState & SCARD_STATE_PRESENT)) {
		char atr[64] = {};
		size_t n = 0;
		for (DWORD i = 0; i < state.cbAtr && n + 3 < sizeof(atr); ++i) {
			std::snprintf(atr + n, 4, "%02X ", state.rgbAtr[i]);
			n += 3;
		}
		*atrOut = atr;
	}
	return (state.dwEventState & SCARD_STATE_PRESENT) != 0;
}

void disconnectCard() {
	if (gCardValid) {
		SCardDisconnect(gCard, SCARD_LEAVE_CARD);
		gCardValid = false;
	}
}

bool connectCard(const std::string &reader) {
	disconnectCard();
	const LONG rc = SCardConnect(
		gContext, reader.c_str(), SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &gCard, &gProtocol);
	if (rc != SCARD_S_SUCCESS) {
		std::printf("  [FAIL] SCardConnect(%s): %s\n", reader.c_str(), scError(rc).c_str());
		return false;
	}
	gCardValid = true;
	std::printf("  connected to \"%s\" (protocol %s)\n", reader.c_str(),
		gProtocol == SCARD_PROTOCOL_T1 ? "T=1" : "T=0");
	return true;
}

bool transmit(const std::vector<unsigned char> &apdu, std::vector<unsigned char> &response) {
	response.clear();
	if (!gCardValid) return false;
	const SCARD_IO_REQUEST *pci =
		(gProtocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;
	std::vector<unsigned char> buffer(65538, 0);
	std::vector<unsigned char> outgoing = apdu;

	for (int attempt = 0; attempt < 2; ++attempt) {
		DWORD received = DWORD(buffer.size());
		const LONG rc = SCardTransmit(
			gCard, pci, outgoing.data(), DWORD(outgoing.size()),
			nullptr, buffer.data(), &received);
		if (rc != SCARD_S_SUCCESS) {
			std::printf("  [FAIL] SCardTransmit: %s\n", scError(rc).c_str());
			disconnectCard();
			return false;
		}
		if (received < 2) {
			disconnectCard();
			return false;
		}
		gSw1 = buffer[received - 2];
		gSw2 = buffer[received - 1];
		response.insert(response.end(), buffer.data(), buffer.data() + received - 2);
		if (gSw1 != 0x6C) break;
		outgoing = apdu;
		outgoing.push_back(gSw2);
		response.clear();
	}
	int guard = 0;
	while (gSw1 == 0x61 && guard++ < 64) {
		const std::vector<unsigned char> getResponse = {0x00, 0xC0, 0x00, 0x00, gSw2};
		DWORD received = DWORD(buffer.size());
		const LONG rc = SCardTransmit(
			gCard, pci, getResponse.data(), DWORD(getResponse.size()),
			nullptr, buffer.data(), &received);
		if (rc != SCARD_S_SUCCESS || received < 2) {
			std::printf("  [FAIL] GET RESPONSE failed\n");
			disconnectCard();
			return false;
		}
		response.insert(response.end(), buffer.data(), buffer.data() + received - 2);
		gSw1 = buffer[received - 2];
		gSw2 = buffer[received - 1];
	}
	return true;
}

// header = CLA INS P1 P2; encodes short/extended Lc + Le per active protocol.
bool transmitPiv(
		const std::vector<unsigned char> &header,
		const std::vector<unsigned char> &body,
		std::vector<unsigned char> &response,
		bool wantsResponse) {
	std::vector<unsigned char> apdu = header;
	if (body.size() <= 255) {
		apdu.push_back((unsigned char)(body.size()));
		apdu.insert(apdu.end(), body.begin(), body.end());
		if (wantsResponse && gProtocol == SCARD_PROTOCOL_T1) {
			apdu.push_back(0x00);
		}
	} else {
		if (gProtocol != SCARD_PROTOCOL_T1) {
			std::printf("  [FAIL] extended APDU needed but protocol is T=0\n");
			return false;
		}
		apdu.push_back(0x00);
		apdu.push_back((unsigned char)(body.size() >> 8));
		apdu.push_back((unsigned char)(body.size() & 0xFF));
		apdu.insert(apdu.end(), body.begin(), body.end());
		apdu.push_back(0x00);
		apdu.push_back(0x00);
	}
	hexdump("APDU>", apdu);
	const bool ok = transmit(apdu, response);
	if (ok) {
		std::vector<unsigned char> shown = response;
		shown.push_back(gSw1);
		shown.push_back(gSw2);
		hexdump("RSP <", shown);
		std::printf("    SW=%02X%02X\n", gSw1, gSw2);
	}
	return ok;
}

// ---------- PIV -------------------------------------------------------------

bool selectPivApplication() {
	const std::vector<std::vector<unsigned char>> aids = {
		{0xA0, 0x00, 0x00, 0x03, 0x08}, // short PIV AID (Yubico style)
		{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00}, // full AID
	};
	for (const auto &aid : aids) {
		std::vector<unsigned char> response;
		const std::vector<unsigned char> header = {0x00, 0xA4, 0x04, 0x00};
		if (!transmitPiv(header, aid, response, false)) return false;
		if (gSw1 == 0x90 && gSw2 == 0x00) {
			std::printf("  PIV card application selected\n");
			return true;
		}
	}
	std::printf("  [FAIL] SELECT AID rejected (SW %02X %02X)\n", gSw1, gSw2);
	return false;
}

bool fetchCertificate9a(std::vector<unsigned char> &der) {
	std::vector<unsigned char> response;
	const std::vector<unsigned char> header = {0x00, 0xCB, 0x3F, 0xFF}; // GET DATA
	const std::vector<unsigned char> body = {0x5C, 0x03, 0x5F, 0xC1, 0x05}; // tag 5FC105
	if (!transmitPiv(header, body, response, true)) return false;
	if (!(gSw1 == 0x90 && gSw2 == 0x00)) {
		std::printf("  [FAIL] GET DATA(5FC105) rejected (SW %02X %02X) — "
			"is a certificate provisioned in slot 9a?\n", gSw1, gSw2);
		return false;
	}
	const auto outer = parseTlvList(response);
	const auto data = findTlv(outer, 0x53);
	if (!data) {
		std::printf("  [FAIL] no 53 data object in GET DATA response\n");
		return false;
	}
	const auto entries = parseTlvList(data->value);
	const auto info = findTlv(entries, 0x71);
	if (info && !info->value.empty() && (info->value[0] & 0x08)) {
		std::printf("  [FAIL] certificate is compressed (unsupported in probe)\n");
		return false;
	}
	const auto cert = findTlv(entries, 0x70);
	if (!cert || cert->value.empty()) {
		std::printf("  [FAIL] no 70 certificate inside 53 object\n");
		return false;
	}
	der = cert->value;
	return true;
}

bool verifyPin(const std::string &pin) {
	std::vector<unsigned char> pinBlock(8, 0xFF);
	std::memcpy(pinBlock.data(), pin.data(), std::min<size_t>(8, pin.size()));
	std::vector<unsigned char> response;
	const std::vector<unsigned char> header = {0x00, 0x20, 0x00, 0x80};
	if (!transmitPiv(header, pinBlock, response, false)) return false;
	if (gSw1 == 0x90 && gSw2 == 0x00) {
		std::printf("  PIN verified\n");
		return true;
	}
	if (gSw1 == 0x63) {
		std::printf("  [FAIL] PIN rejected, %d attempt(s) remaining\n", gSw2 & 0x0F);
	} else {
		std::printf("  [FAIL] VERIFY PIN SW %02X %02X\n", gSw1, gSw2);
	}
	return false;
}

std::vector<unsigned char> buildPkcs1V15Sha256Em(const unsigned char *digest) {
	static const unsigned char kDigestInfo[] = {
		0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	};
	constexpr size_t kModulus = 256; // RSA-2048
	const size_t tLength = sizeof(kDigestInfo) + SHA256_DIGEST_LENGTH;
	std::vector<unsigned char> em(kModulus, 0xFF);
	em[0] = 0x00;
	em[1] = 0x01;
	const size_t ffLength = kModulus - 3 - tLength;
	em[2 + ffLength] = 0x00;
	std::memcpy(em.data() + 3 + ffLength, kDigestInfo, sizeof(kDigestInfo));
	std::memcpy(em.data() + 3 + ffLength + sizeof(kDigestInfo), digest,
		SHA256_DIGEST_LENGTH);
	return em;
}

bool signWith9a(const std::string &message, std::vector<unsigned char> &signature) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
	::SHA256(reinterpret_cast<const unsigned char *>(message.data()),
		message.size(), digest);
	const auto em = buildPkcs1V15Sha256Em(digest);

	std::vector<unsigned char> body;
	body.push_back(0x7C);
	// outer 7C value = 81 hdr(2) + len hdr(2) + EM
	body.push_back(0x82);
	body.push_back((unsigned char)((em.size() + 4) >> 8));
	body.push_back((unsigned char)((em.size() + 4) & 0xFF));
	body.push_back(0x81);
	body.push_back(0x82);
	body.push_back((unsigned char)(em.size() >> 8));
	body.push_back((unsigned char)(em.size() & 0xFF));
	body.insert(body.end(), em.begin(), em.end());

	std::vector<unsigned char> response;
	const std::vector<unsigned char> header = {0x00, 0x87, 0x07, 0x9A}; // GA, alg 7, key 9A
	if (!transmitPiv(header, body, response, true)) return false;
	if (!(gSw1 == 0x90 && gSw2 == 0x00)) {
		if (gSw1 == 0x63) {
			std::printf("  [NEED-PIN] GENERAL AUTHENTICATE returned 63 %02X "
				"(%d attempt(s) left) — PIN required for slot 9a\n", gSw2, gSw2 & 0x0F);
		} else {
			std::printf("  [FAIL] GENERAL AUTHENTICATE SW %02X %02X\n", gSw1, gSw2);
		}
		return false;
	}
	const auto outer = parseTlvList(response);
	const auto templ = findTlv(outer, 0x7C);
	if (!templ) {
		std::printf("  [FAIL] no 7C template in signature response\n");
		return false;
	}
	const auto inner = parseTlvList(templ->value);
	const auto sig = findTlv(inner, 0x82);
	if (!sig || sig->value.empty()) {
		std::printf("  [FAIL] no 82 signature inside 7C template\n");
		return false;
	}
	signature = sig->value;
	return true;
}

// ---------- misc ------------------------------------------------------------

std::string readPinFromTty() {
	std::printf("  Enter PIV PIN (default YubiKey PIN is 123456): ");
	std::fflush(stdout);
	std::string pin;
	termios saved = {};
	const int fd = fileno(stdin);
	if (isatty(fd)) {
		tcgetattr(fd, &saved);
		termios hidden = saved;
		hidden.c_lflag &= ~ECHO;
		tcsetattr(fd, TCSAFLUSH, &hidden);
	}
	char buffer[64] = {};
	if (std::fgets(buffer, sizeof(buffer), stdin)) {
		pin = buffer;
		while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) {
			pin.pop_back();
		}
	}
	if (isatty(fd)) {
		tcsetattr(fd, TCSAFLUSH, &saved);
		std::printf("\n");
	}
	return pin;
}

} // namespace

int main() {
	std::printf("==============================================\n");
	std::printf("CRYPTOGRAM CAC/PIV probe (PC/SC + PIV, 9a)\n");
	std::printf("==============================================\n");

	// ---- 1. readers --------------------------------------------------------
	if (!establishContext()) {
		std::printf("[SKIP] PC/SC not available (install libpcsclite1 / start pcscd).\n");
		return 0;
	}
	const auto readers = listReaders();
	if (readers.empty()) {
		std::printf("[SKIP] No PC/SC readers found.\n");
		std::printf(">>> Plug in the FIPS YubiKey (CCID interface) and re-run:\n");
		std::printf(">>>   ./build_tests/tests/unit/test_cac_piv_probe\n");
		std::printf(">>> If it still does not show up: ensure pcscd is running and the\n");
		std::printf(">>> YubiKey is in CCID mode (`ykman config usb --enable CCID`).\n");
		return 0;
	}
	std::printf("[PASS] PC/SC readers found: %zu\n", readers.size());
	for (const auto &reader : readers) {
		std::printf("  - %s\n", reader.c_str());
	}

	// ---- 2. bounded wait for a card ----------------------------------------
	const char *waitEnv = std::getenv("CAC_PROBE_WAIT_SECS");
	const int waitSeconds = waitEnv ? std::atoi(waitEnv) : 5;
	std::string reader;
	std::string atr;
	for (int elapsed = 0;; ++elapsed) {
		for (const auto &candidate : readers) {
			if (readerHasCard(candidate, &atr)) {
				reader = candidate;
				break;
			}
		}
		if (!reader.empty()) break;
		if (elapsed >= waitSeconds) break;
		if (elapsed == 0) {
			std::printf("  No card present yet.\n");
			std::printf(">>> Plug in the FIPS YubiKey now (waiting up to %d s,\n", waitSeconds);
			std::printf(">>> CAC_PROBE_WAIT_SECS to change). If PIN/touch is requested\n");
			std::printf(">>> during signing, follow the device prompt.\n");
		}
		sleep(1);
	}
	if (reader.empty()) {
		std::printf("[SKIP] No card in any reader after %d s.\n", waitSeconds);
		std::printf(">>> Plug in the FIPS YubiKey and re-run:\n");
		std::printf(">>>   ./build_tests/tests/unit/test_cac_piv_probe\n");
		return 0;
	}
	std::printf("[PASS] Card present on \"%s\" (ATR: %s)\n", reader.c_str(), atr.c_str());
	CHECK(!atr.empty());
	if (!connectCard(reader)) {
		std::printf("[FAIL] could not connect to the card\n");
		return 1;
	}
	CHECK(gCardValid);

	// ---- 3. PIV applet ------------------------------------------------------
	if (!selectPivApplication()) {
		std::printf("[FAIL] PIV applet not selectable — is the YubiKey PIV-enabled?\n");
		return 1;
	}
	CHECK(true);

	// ---- 4. certificate in slot 9a ------------------------------------------
	std::vector<unsigned char> der;
	if (!fetchCertificate9a(der)) {
		std::printf("[FAIL] could not read the 9a certificate.\n");
		std::printf(">>> Provision one with yubico-piv-tool, see\n");
		std::printf(">>> docs/CAC_YUBIKEY_PROVISIONING.md\n");
		return 1;
	}
	std::printf("[PASS] 9a certificate fetched (%zu bytes DER)\n", der.size());
	CHECK(der.size() > 64);

	const unsigned char *derPointer = der.data();
	X509 *x509 = d2i_X509(nullptr, &derPointer, unsigned(der.size()));
	if (!x509) {
		std::printf("[FAIL] d2i_X509 failed on the fetched object\n");
		return 1;
	}
	{
		char line[512] = {};
		X509_NAME_oneline(X509_get_subject_name(x509), line, sizeof(line));
		std::printf("  subject : %s\n", line);
		X509_NAME_oneline(X509_get_issuer_name(x509), line, sizeof(line));
		std::printf("  issuer  : %s\n", line);
		const ASN1_INTEGER *serial = X509_get_serialNumber(x509);
		if (serial) {
			BIGNUM *bn = BN_new();
			if (bn && ASN1_INTEGER_to_BN(serial, bn)) {
				char *hex = BN_bn2hex(bn);
				if (hex) {
					std::printf("  serial  : %s\n", hex);
					OPENSSL_free(hex);
				}
			}
			BN_free(bn);
		}
		const ASN1_TIME *notAfter = X509_get_notAfter(x509);
		if (notAfter) {
			struct tm tmValue = {};
			if (ASN1_TIME_to_tm(notAfter, &tmValue)) {
				std::printf("  expires : %04d-%02d-%02d %02d:%02d:%02d UTC\n",
					tmValue.tm_year + 1900, tmValue.tm_mon + 1, tmValue.tm_mday,
					tmValue.tm_hour, tmValue.tm_min, tmValue.tm_sec);
			}
		}
	}
	CHECK(X509_get_pubkey(x509) != nullptr);

	// ---- 5. sign a test vector (RSA-2048 PKCS#1 v1.5 / SHA-256, key 9A) -----
	const std::string message = "CRYPTOGRAM CAC/PIV probe test vector\n";
	std::printf("  signing: \"%s\"\n", message.c_str());
	std::printf("  (touch the YubiKey if it blinks; signing may block until touch)\n");
	std::vector<unsigned char> signature;
	if (!signWith9a(message, signature)) {
		if (gSw1 == 0x63) {
			// PIN required for slot 9a (YubiKey default pin-policy=once).
			std::string pin = [] {
				const char *env = std::getenv("CAC_PROBE_PIN");
				return env ? std::string(env) : std::string();
			}();
			if (pin.empty() && isatty(fileno(stdin))) {
				pin = readPinFromTty();
			}
			if (pin.empty()) {
				std::printf("[SKIP] PIN required. Re-run with the PIN:\n");
				std::printf(">>>   CAC_PROBE_PIN=123456 ./build_tests/tests/unit/test_cac_piv_probe\n");
				X509_free(x509);
				return 0;
			}
			if (!verifyPin(pin)) {
				X509_free(x509);
				return 1;
			}
			if (!signWith9a(message, signature)) {
				X509_free(x509);
				return 1;
			}
		} else {
			X509_free(x509);
			return 1;
		}
	}
	std::printf("[PASS] signature produced (%zu bytes)\n", signature.size());
	CHECK(signature.size() == 256); // RSA-2048

	// ---- 6. verify the signature with the certificate public key ------------
	bool verified = false;
	if (EVP_PKEY *publicKey = X509_get_pubkey(x509)) {
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		if (ctx
			&& EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) == 1) {
			verified = EVP_DigestVerify(
				ctx,
				signature.data(),
				signature.size(),
				reinterpret_cast<const unsigned char *>(message.data()),
				message.size()) == 1;
		}
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(publicKey);
	}
	CHECK(verified);
	X509_free(x509);

	if (verified) {
		std::printf("[PASS] signature verifies against the 9a certificate\n");
	} else {
		std::printf("[FAIL] signature does NOT verify\n");
	}

	std::printf("----------------------------------------------\n");
	std::printf("Probe: %d check(s), %d failure(s) — %s\n",
		gChecks, gFailures, (gFailures == 0) ? "PASS" : "FAIL");
	std::printf("What this proved: PC/SC transport, PIV applet select, X.509 9a\n");
	std::printf("read, hardware-backed RSA-2048 sign + local verification.\n");
	std::printf("What DoD-CAC adds: chain trust to NATO/DoD roots via\n");
	std::printf("SignalProtocol::verifyCacMutualAuth (docs/CAC_YUBIKEY_PROVISIONING.md).\n");
	return (gFailures == 0) ? 0 : 1;
}
