// Real ML-KEM + AES-256-GCM round trips through the production QuantumGuard
// code path: generateQuantumKey → importPeerKemPublicKey(Raw) →
// quantumEncrypt / quantumEncapsulate → quantumDecrypt, plus tamper,
// wrong-key and persistence cases. Unlike the earlier standalone suites
// this exercises data_quantumguard.cpp itself, not a re-implementation.

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "data/data_quantumguard.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QUuid>

#include <cstring>

using namespace Data;

namespace {

bytes::vector makePlaintext(int size) {
	bytes::vector out(size);
	for (int i = 0; i != size; ++i) {
		out[i] = bytes::type('a' + (i % 26));
	}
	return out;
}

// Export the raw ML-KEM public key as SubjectPublicKeyInfo DER, the same
// encoding SignalProtocol advertises inside key-bundle entities.
QByteArray rawToSpkiDer(
		QuantumAlgorithm algorithm,
		const QByteArray &rawPublicKey) {
	const auto type = (algorithm == QuantumAlgorithm::ML_KEM_512)
		? NID_ML_KEM_512
		: (algorithm == QuantumAlgorithm::ML_KEM_768)
			? NID_ML_KEM_768
			: NID_ML_KEM_1024;
	auto *pkey = EVP_PKEY_new_raw_public_key(
		type,
		nullptr,
		reinterpret_cast<const unsigned char *>(rawPublicKey.constData()),
		size_t(rawPublicKey.size()));
	REQUIRE(pkey != nullptr);
	unsigned char *der = nullptr;
	const auto derLen = i2d_PUBKEY(pkey, &der);
	EVP_PKEY_free(pkey);
	REQUIRE(derLen > 0);
	REQUIRE(der != nullptr);
	QByteArray result(reinterpret_cast<const char *>(der), derLen);
	OPENSSL_free(der);
	return result;
}

} // namespace

TEST_CASE("QuantumGuard KEM roundtrip", "[quantum][kem]") {
	QuantumGuard alice;
	QuantumGuard bob;
	REQUIRE(alice.initialize());
	REQUIRE(bob.initialize());

	auto bobKey = bob.generateQuantumKey(
		QuantumKeyType::Encapsulation,
		QuantumAlgorithm::ML_KEM_1024);
	REQUIRE(bobKey.has_value());
	REQUIRE(bobKey->publicKey.size() > 1000);

	// Alice encapsulates against Bob's advertised public key.
	REQUIRE(alice.importPeerKemPublicKeyRaw(
		"peer-bob",
		QuantumAlgorithm::ML_KEM_1024,
		bobKey->publicKey).has_value());

	const auto plaintext = makePlaintext(1024);
	auto encrypted = alice.quantumEncrypt("peer-bob", bytes::make_span(plaintext));
	REQUIRE(encrypted.has_value());
	REQUIRE(encrypted->encapsulatedSecret.size() > 1000);
	REQUIRE(encrypted->ciphertext.size() == plaintext.size());

	// Bob decapsulates with his private half and recovers the plaintext.
	auto decrypted = bob.quantumDecrypt(
		bobKey->keyId,
		encrypted->ciphertext,
		encrypted->encapsulatedSecret,
		encrypted->iv,
		encrypted->authTag);
	REQUIRE(decrypted.has_value());
	REQUIRE(decrypted->size() == plaintext.size());
	REQUIRE(std::memcmp(decrypted->data(), plaintext.data(), plaintext.size()) == 0);

	// A flipped ciphertext bit must fail authentication.
	auto tampered = encrypted->ciphertext;
	tampered[0] = bytes::type(uint8(tampered[0]) ^ 0x01);
	auto bad = bob.quantumDecrypt(
		bobKey->keyId,
		tampered,
		encrypted->encapsulatedSecret,
		encrypted->iv,
		encrypted->authTag);
	REQUIRE_FALSE(bad.has_value());
}

TEST_CASE("QuantumGuard SPKI DER import", "[quantum][kem]") {
	QuantumGuard alice;
	QuantumGuard bob;
	REQUIRE(alice.initialize());
	REQUIRE(bob.initialize());

	auto bobKey = bob.generateQuantumKey(
		QuantumKeyType::Encapsulation,
		QuantumAlgorithm::ML_KEM_1024);
	REQUIRE(bobKey.has_value());

	const auto der = rawToSpkiDer(
		QuantumAlgorithm::ML_KEM_1024,
		bobKey->publicKey);
	REQUIRE(der.size() > 1000);

	auto importedDer = alice.importPeerKemPublicKey(
		"peer-bob-der",
		QuantumAlgorithm::Unknown,
		der);
	if (!importedDer) {
		FAIL(importedDer.error().toStdString());
	}

	const auto plaintext = makePlaintext(256);
	auto encrypted = alice.quantumEncrypt(
		"peer-bob-der",
		bytes::make_span(plaintext));
	REQUIRE(encrypted.has_value());

	auto decrypted = bob.quantumDecrypt(
		bobKey->keyId,
		encrypted->ciphertext,
		encrypted->encapsulatedSecret,
		encrypted->iv,
		encrypted->authTag);
	REQUIRE(decrypted.has_value());
	REQUIRE(std::memcmp(decrypted->data(), plaintext.data(), plaintext.size()) == 0);

	// A third party's key must NOT decapsulate Bob's session.
	QuantumGuard mallory;
	REQUIRE(mallory.initialize());
	auto malloryKey = mallory.generateQuantumKey(
		QuantumKeyType::Encapsulation,
		QuantumAlgorithm::ML_KEM_1024);
	REQUIRE(malloryKey.has_value());
	auto wrong = mallory.quantumDecrypt(
		malloryKey->keyId,
		encrypted->ciphertext,
		encrypted->encapsulatedSecret,
		encrypted->iv,
		encrypted->authTag);
	REQUIRE_FALSE(wrong.has_value());
}

TEST_CASE("QuantumGuard bare encapsulation", "[quantum][kem]") {
	QuantumGuard alice;
	QuantumGuard bob;
	REQUIRE(alice.initialize());
	REQUIRE(bob.initialize());

	auto bobKey = bob.generateQuantumKey(
		QuantumKeyType::Encapsulation,
		QuantumAlgorithm::ML_KEM_1024);
	REQUIRE(bobKey.has_value());
	REQUIRE(alice.importPeerKemPublicKeyRaw(
		"peer-bob",
		QuantumAlgorithm::ML_KEM_1024,
		bobKey->publicKey).has_value());

	auto kem = alice.quantumEncapsulate("peer-bob");
	REQUIRE(kem.has_value());
	REQUIRE(kem->sharedSecret.size() >= 32);
	REQUIRE(kem->ciphertext.size() > 1000);

	// Bob decapsulates the bare ciphertext to the SAME shared secret.
	auto shared = bob.quantumDecapsulate(
		bobKey->keyId,
		bytes::make_span(kem->ciphertext));
	REQUIRE(shared.has_value());
	REQUIRE(shared->size() == kem->sharedSecret.size());
	REQUIRE(std::memcmp(
		shared->data(),
		kem->sharedSecret.data(),
		kem->sharedSecret.size()) == 0);

	// A wrong private key decapsulates to a DIFFERENT secret (ML-KEM
	// implicit rejection still yields output, never the peer's secret).
	QuantumGuard mallory;
	REQUIRE(mallory.initialize());
	auto malloryKey = mallory.generateQuantumKey(
		QuantumKeyType::Encapsulation,
		QuantumAlgorithm::ML_KEM_1024);
	REQUIRE(malloryKey.has_value());
	auto wrong = mallory.quantumDecapsulate(
		malloryKey->keyId,
		bytes::make_span(kem->ciphertext));
	REQUIRE(wrong.has_value());
	REQUIRE(std::memcmp(
		wrong->data(),
		kem->sharedSecret.data(),
		kem->sharedSecret.size()) != 0);
}

TEST_CASE("QuantumGuard key persistence roundtrip", "[quantum][persistence]") {
	QuantumGuard alice;
	REQUIRE(alice.initialize());

	auto key = alice.generateQuantumKey(
		QuantumKeyType::Encapsulation,
		QuantumAlgorithm::ML_KEM_1024);
	REQUIRE(key.has_value());

	const auto dir = QDir::temp().filePath(
		u"cryptogram-quantum-test-%1"_q.arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
	QDir().mkpath(dir);
	const auto keyPath = dir + u"/identity.qgk"_q;
	const auto password = QByteArray("test-wrapping-password");

	REQUIRE(alice.saveKeys(keyPath, password));
	REQUIRE(QFile::exists(keyPath));

	// A fresh process-equivalent guard restores the keypair by keyId.
	QuantumGuard restored;
	REQUIRE(restored.initialize());
	REQUIRE(restored.loadKeys(keyPath, password));

	const auto plaintext = makePlaintext(128);
	auto encrypted = alice.quantumEncrypt(
		key->keyId,
		bytes::make_span(plaintext));
	REQUIRE(encrypted.has_value());

	auto decrypted = restored.quantumDecrypt(
		key->keyId,
		encrypted->ciphertext,
		encrypted->encapsulatedSecret,
		encrypted->iv,
		encrypted->authTag);
	REQUIRE(decrypted.has_value());
	REQUIRE(std::memcmp(decrypted->data(), plaintext.data(), plaintext.size()) == 0);

	// Wrong password must not restore the keys.
	QuantumGuard wrongPw;
	REQUIRE(wrongPw.initialize());
	REQUIRE_FALSE(wrongPw.loadKeys(keyPath, QByteArray("wrong-password")));

	QDir(dir).removeRecursively();
}
