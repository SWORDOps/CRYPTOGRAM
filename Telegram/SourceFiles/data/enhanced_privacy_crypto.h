/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

// Self-contained passphrase crypto for Enhanced Privacy and the covert
// channel: PBKDF2-HMAC-SHA-256 key derivation plus salted AES-256-GCM with
// a versioned envelope. Deliberately depends on nothing but QtCore and
// OpenSSL so it can be compiled directly into standalone test binaries.
namespace EnhancedPrivacyCrypto {

constexpr int kPbkdf2Iterations = 200000;
constexpr int kSaltSize = 16;

// PBKDF2-HMAC-SHA-256, 32-byte output. Exposed for tests.
QByteArray DeriveKey(const QString &passphrase, const QByteArray &salt, int iterations);

// New format: "CR2:" + base64(salt[16] || iv[12] || ciphertext || tag[16])
// Key = PBKDF2-HMAC-SHA-256(passphrase, salt, kPbkdf2Iterations, 32).
QString EncryptString(const QString &text, const QString &passphrase);

// Routes on the "CR2:" prefix; legacy input (no prefix) uses the old
// algorithm (unsalted single-round SHA-256 key over base64(iv || ct || tag))
// so payloads persisted by older builds still decrypt.
// Returns an empty QString on failure (existing caller contract).
QString DecryptString(const QString &text, const QString &passphrase);

} // namespace EnhancedPrivacyCrypto
