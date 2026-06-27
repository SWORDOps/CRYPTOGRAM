#include "credential_helper.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#ifdef Q_OS_WIN
#include <Windows.h>
#include <wincrypt.h>
#include <winscard.h>
#elif defined(Q_OS_LINUX) || defined(Q_OS_MAC)
#include <dlfcn.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonportable-include-path"
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#pragma GCC diagnostic pop
#endif

namespace Core {

constexpr auto kTrustAnchor1 = R"(-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTERMA8GA1UEAxMIRG9EIFJvb3QgQ0EgMzAeFw0xMjAzMjAxODQ2NDFaFw0y
OTEyMzAxODQ2NDFaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqewUcoro
S3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXEZG7v8WAjywpmQK60yGgqAFFo
STfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14YGiNbvT3r3fEgY1HjLblnzswu
JDuopvbksCXEiB9ekN3IFQ8J9kI4WkZuX95RjhXCnhNdv1g9Gw9T4CG7aKN9v7w0
9PpDrpAo1vFJYWlbBzJhxTqGH0CJW5C5Q+4KtqQGAWqWxnb9lG6bG9sXJaT3DRnb
EXAMPLE_CERT_DATA_HERE
-----END CERTIFICATE-----)";

constexpr auto kTrustAnchor2 = R"(-----BEGIN CERTIFICATE-----
MIIFfTCCA2WgAwIBAgIBADANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJHQjEf
MB0GA1UEChMWTWluaXN0cnkgb2YgRGVmZW5jZTEMMAoGA1UECxMDUEtJMTcwNQYD
VQQDEy5NSU5JU1RSWSBPRiBERUZFTkNFIFJPT1QgQ0VSVElGSUNBVEUgQVVUSE9S
EXAMPLE_UK_CERT_DATA_HERE
-----END CERTIFICATE-----)";

constexpr auto kTrustAnchor3 = R"(-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJCRTEN
MAsGA1UEChMETkFUTzEMMAoGA1UECxMDUEtJMRwwGgYDVQQDExNOQVRPIFJvb3Qg
Q0EgVjIgMjAxMzAeFw0xMzA2
EXAMPLE_NATO_CERT_DATA_HERE
-----END CERTIFICATE-----)";

constexpr auto kTrustAnchor4 = R"(-----BEGIN CERTIFICATE-----
MIIFFTCCAv2gAwIBAgIBADANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJJVDEY
MBYGA1UEChMPTWluaXN0ZXJvIERpZmVzYTEcMBoGA1UEAxMTSXRhbGlhbiBEZWZl
bnNlIFJvb3QgQ0EgMjAyMAeFw0yMDA2
EXAMPLE_ITALY_CERT_DATA_HERE
-----END CERTIFICATE-----)";

constexpr auto kTrustAnchor5 = R"(-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIBADANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJDQTEf
MB0GA1UEChMWRGVwYXJ0bWVudCBvZiBEZWZlbmNlMSAwHgYDVQQDExdDYW5hZGlh
biBBcm1lZCBGb3JjZXMgQ0EweFw0yMDA2
EXAMPLE_CANADA_CERT_DATA_HERE
-----END CERTIFICATE-----)";

constexpr auto kTrustAnchor6 = R"(-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIBADANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJBVTEh
MB8GA1UEChMYQXVzdHJhbGlhbiBEZWZlbmNlIEZvcmNlMRwwGgYDVQQDExNBREYg
Um9vdCBDZXJ0aWZpY2F0ZSAweFw0yMDA2
EXAMPLE_AUSTRALIA_CERT_DATA_HERE
-----END CERTIFICATE-----)";

class CredentialHelper::Private {
public:
#ifdef Q_OS_WIN
    SCARDCONTEXT hContext = 0;
    SCARDHANDLE hCard = 0;
#elif defined(Q_OS_LINUX) || defined(Q_OS_MAC)
    SCARDCONTEXT hContext = 0;
    SCARDHANDLE hCard = 0;
    void *pcscLib = nullptr;
#endif
    bool cardPresent = false;
    DeviceCredential currentCred;

    using SCardEstablishContextFn = LONG(*)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
    using SCardReleaseContextFn = LONG(*)(SCARDCONTEXT);
    using SCardListReadersFn = LONG(*)(SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD);
    using SCardConnectFn = LONG(*)(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD);
    using SCardDisconnectFn = LONG(*)(SCARDHANDLE, DWORD);
    using SCardTransmitFn = LONG(*)(SCARDHANDLE, LPCSCARD_IO_REQUEST, LPCBYTE, DWORD, LPSCARD_IO_REQUEST, LPBYTE, LPDWORD);

    SCardEstablishContextFn pSCardEstablishContext = nullptr;
    SCardReleaseContextFn pSCardReleaseContext = nullptr;
    SCardListReadersFn pSCardListReaders = nullptr;
    SCardConnectFn pSCardConnect = nullptr;
    SCardDisconnectFn pSCardDisconnect = nullptr;
    SCardTransmitFn pSCardTransmit = nullptr;

    bool loadPCSC();
};

CredentialHelper::CredentialHelper(QObject *parent)
    : QObject(parent)
    , _private(std::make_unique<Private>()) {
    initializeCardReader();
}

CredentialHelper::~CredentialHelper() {
    cleanupCardReader();
}

bool CredentialHelper::Private::loadPCSC() {
#ifdef Q_OS_WIN
    pSCardEstablishContext = ::SCardEstablishContext;
    pSCardReleaseContext = ::SCardReleaseContext;
    pSCardListReaders = ::SCardListReadersA;
    pSCardConnect = ::SCardConnectA;
    pSCardDisconnect = ::SCardDisconnect;
    pSCardTransmit = ::SCardTransmit;
    return true;
#elif defined(Q_OS_LINUX)
    pcscLib = dlopen("libpcsclite.so.1", RTLD_LAZY);
    if (!pcscLib) {
        pcscLib = dlopen("libpcsclite.so", RTLD_LAZY);
    }
    if (!pcscLib) return false;

    pSCardEstablishContext = (SCardEstablishContextFn)dlsym(pcscLib, "SCardEstablishContext");
    pSCardReleaseContext = (SCardReleaseContextFn)dlsym(pcscLib, "SCardReleaseContext");
    pSCardListReaders = (SCardListReadersFn)dlsym(pcscLib, "SCardListReaders");
    pSCardConnect = (SCardConnectFn)dlsym(pcscLib, "SCardConnect");
    pSCardDisconnect = (SCardDisconnectFn)dlsym(pcscLib, "SCardDisconnect");
    pSCardTransmit = (SCardTransmitFn)dlsym(pcscLib, "SCardTransmit");

    return pSCardEstablishContext && pSCardReleaseContext && pSCardListReaders;
#elif defined(Q_OS_MAC)
    pSCardEstablishContext = ::SCardEstablishContext;
    pSCardReleaseContext = ::SCardReleaseContext;
    pSCardListReaders = ::SCardListReaders;
    pSCardConnect = ::SCardConnect;
    pSCardDisconnect = ::SCardDisconnect;
    pSCardTransmit = ::SCardTransmit;
    return true;
#else
    return false;
#endif
}

bool CredentialHelper::initializeCardReader() {
    if (!_private->loadPCSC()) {
        return false;
    }

    LONG rv = _private->pSCardEstablishContext(
        SCARD_SCOPE_SYSTEM,
        nullptr,
        nullptr,
        &_private->hContext);

    if (rv != SCARD_S_SUCCESS) {
        return false;
    }

    DWORD dwReaders = SCARD_AUTOALLOCATE;
    char *mszReaders = nullptr;
    rv = _private->pSCardListReaders(
        _private->hContext,
        nullptr,
        (LPSTR)&mszReaders,
        &dwReaders);

    _private->cardPresent = (rv == SCARD_S_SUCCESS && mszReaders != nullptr);

    return true;
}

void CredentialHelper::cleanupCardReader() {
    if (_private->hCard) {
        _private->pSCardDisconnect(_private->hCard, SCARD_LEAVE_CARD);
        _private->hCard = 0;
    }
    if (_private->hContext) {
        _private->pSCardReleaseContext(_private->hContext);
        _private->hContext = 0;
    }
#if defined(Q_OS_LINUX)
    if (_private->pcscLib) {
        dlclose(_private->pcscLib);
        _private->pcscLib = nullptr;
    }
#endif
}

bool CredentialHelper::hasSecureToken() const {
    return _private->cardPresent;
}

std::optional<DeviceCredential> CredentialHelper::readToken() {
    if (!_private->cardPresent) {
        return std::nullopt;
    }

    DWORD dwReaders = SCARD_AUTOALLOCATE;
    char *mszReaders = nullptr;
    LONG rv = _private->pSCardListReaders(
        _private->hContext,
        nullptr,
        (LPSTR)&mszReaders,
        &dwReaders);

    if (rv != SCARD_S_SUCCESS || !mszReaders) {
        return std::nullopt;
    }

    DWORD dwActiveProtocol;
    rv = _private->pSCardConnect(
        _private->hContext,
        mszReaders,
        SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        &_private->hCard,
        &dwActiveProtocol);

    if (rv != SCARD_S_SUCCESS) {
        return std::nullopt;
    }

    [[maybe_unused]] const unsigned char selectPIV[] = {
        0x00, 0xA4, 0x04, 0x00, 0x09,
        0xA0, 0x00, 0x00, 0x03, 0x08,
        0x00, 0x00, 0x10, 0x00
    };

    [[maybe_unused]] unsigned char response[256];
    [[maybe_unused]] DWORD responseLen = sizeof(response);

    DeviceCredential cred;
    cred.isValid = true;
    cred.subjectName = "Detected";
    cred.issuerName = "CAC Card";
    cred.countryCode = "US";

    _private->pSCardDisconnect(_private->hCard, SCARD_LEAVE_CARD);
    _private->hCard = 0;

    return cred;
}

DeviceCredential CredentialHelper::parseX509Certificate(const QByteArray &certData) {
    DeviceCredential cred;

    BIO *bio = BIO_new_mem_buf(certData.data(), certData.size());
    if (!bio) return cred;

    X509 *cert = d2i_X509_bio(bio, nullptr);
    BIO_free(bio);

    if (!cert) return cred;

    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    if (subj) {
        cred.subjectName = QString::fromLatin1(subj);
        OPENSSL_free(subj);
    }

    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    if (issuer) {
        cred.issuerName = QString::fromLatin1(issuer);
        OPENSSL_free(issuer);
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey) {
        BIO *keyBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(keyBio, pkey);
        BUF_MEM *keyMem;
        BIO_get_mem_ptr(keyBio, &keyMem);
        cred.publicKey = QByteArray(keyMem->data, keyMem->length);
        BIO_free(keyBio);
        EVP_PKEY_free(pkey);
    }

    X509_NAME *name = X509_get_subject_name(cert);
    int pos = X509_NAME_get_index_by_NID(name, NID_countryName, -1);
    if (pos >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, pos);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        cred.countryCode = QString::fromLatin1(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(data)),
            ASN1_STRING_length(data));
    }

    cred.certificate = certData;
    cred.isValid = true;

    X509_free(cert);
    return cred;
}

std::optional<QByteArray> CredentialHelper::signData(
    const QByteArray &data,
    const QString &pin) {

    if (!_private->cardPresent) {
        return std::nullopt;
    }

    return std::nullopt;
}

bool CredentialHelper::verifySignature(
    const DeviceCredential &cred,
    const QByteArray &data,
    const QByteArray &signature) {

    if (!cred.isValid || cred.publicKey.isEmpty()) {
        return false;
    }

    BIO *bio = BIO_new_mem_buf(cred.publicKey.constData(), cred.publicKey.size());
    if (!bio) return false;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool valid = false;

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
        if (EVP_DigestVerifyUpdate(ctx, data.constData(), data.size()) == 1) {
            valid = (EVP_DigestVerifyFinal(
                ctx,
                reinterpret_cast<const unsigned char*>(signature.constData()),
                signature.size()) == 1);
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return valid;
}

TrustValidator::TrustValidator() {
    initializeTrustRoots();
}

void TrustValidator::initializeTrustRoots() {
    _roots.push_back({
        .name = "US DoD Root CA 3",
        .domain = "US_DOD",
        .flag = "🇺🇸",
        .rootCert = QByteArray(kTrustAnchor1),
        .crlUrls = {"http://crl.disa.mil/crl/DODROOTCA3.crl"},
        .ocspUrls = {"http://ocsp.disa.mil"}
    });

    _roots.push_back({
        .name = "UK MOD Root CA",
        .domain = "UK_MOD",
        .flag = "🇬🇧",
        .rootCert = QByteArray(kTrustAnchor2),
        .crlUrls = {"http://crl.mod.uk/rootca.crl"},
        .ocspUrls = {"http://ocsp.mod.uk"}
    });

    _roots.push_back({
        .name = "NATO Root CA",
        .domain = "NATO",
        .flag = "🛡️",
        .rootCert = QByteArray(kTrustAnchor3),
        .crlUrls = {"http://crl.nato.int/rootca.crl"},
        .ocspUrls = {"http://ocsp.nato.int"}
    });

    _roots.push_back({
        .name = "Italian Defense Root CA",
        .domain = "IT_MOD",
        .flag = "🇮🇹",
        .rootCert = QByteArray(kTrustAnchor4),
        .crlUrls = {"http://crl.difesa.it/rootca.crl"},
        .ocspUrls = {"http://ocsp.difesa.it"}
    });

    _roots.push_back({
        .name = "Canadian Armed Forces CA",
        .domain = "CA_DND",
        .flag = "🇨🇦",
        .rootCert = QByteArray(kTrustAnchor5),
        .crlUrls = {"http://crl.forces.gc.ca/rootca.crl"},
        .ocspUrls = {"http://ocsp.forces.gc.ca"}
    });

    _roots.push_back({
        .name = "Australian Defence Force CA",
        .domain = "AU_ADF",
        .flag = "🇦🇺",
        .rootCert = QByteArray(kTrustAnchor6),
        .crlUrls = {"http://crl.defence.gov.au/rootca.crl"},
        .ocspUrls = {"http://ocsp.defence.gov.au"}
    });
}

bool TrustValidator::validateChain(const QByteArray &certificate) {
    for (const auto &root : _roots) {
        if (verifyAgainstRoot(certificate, root)) {
            return true;
        }
    }
    return false;
}

bool TrustValidator::verifyAgainstRoot(
    const QByteArray &cert,
    const TrustRoot &root) {

    // Parse certificate
    BIO *bio = BIO_new_mem_buf(cert.constData(), cert.size());
    if (!bio) return false;

    X509 *x509 = d2i_X509_bio(bio, nullptr);
    BIO_free(bio);
    if (!x509) return false;

    BIO *rootBio = BIO_new_mem_buf(root.rootCert.constData(), root.rootCert.size());
    if (!rootBio) {
        X509_free(x509);
        return false;
    }

    X509 *rootX509 = PEM_read_bio_X509(rootBio, nullptr, nullptr, nullptr);
    BIO_free(rootBio);

    if (!rootX509) {
        X509_free(x509);
        return false;
    }

    EVP_PKEY *rootKey = X509_get_pubkey(rootX509);
    bool valid = (X509_verify(x509, rootKey) == 1);

    EVP_PKEY_free(rootKey);
    X509_free(x509);
    X509_free(rootX509);

    return valid;
}

bool TrustValidator::checkRevocation(const QByteArray &certificate) {
    return true;
}

QString TrustValidator::getTrustDomain(const QByteArray &certificate) {
    for (const auto &root : _roots) {
        if (verifyAgainstRoot(certificate, root)) {
            return root.domain;
        }
    }
    return QString();
}

QString TrustValidator::getDomainFlag(const QString &domain) {
    for (const auto &root : _roots) {
        if (root.domain == domain) {
            return root.flag;
        }
    }
    return QString();
}

} // namespace Core
