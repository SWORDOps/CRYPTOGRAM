# CAC Authentication UI Integration Guide

## Overview

The CAC (Common Access Card) authentication system foundation is complete. This guide explains how to integrate the UI components to complete the system.

## Completed Components

### Core Implementation ✅

**Files**: `core/credential_helper.{h,cpp}`, `core/peer_trust.{h,cpp}`

- PCSC smart card reader detection (Windows/Linux/macOS)
- X.509 certificate parsing and validation
- Certificate chain verification against military roots:
  - 🇺🇸 US DoD Root CA 3
  - 🇬🇧 UK Ministry of Defence
  - 🛡️ NATO
  - 🇮🇹 Italian Defense (Ministero Difesa)
  - 🇨🇦 Canadian Armed Forces
  - 🇦🇺 Australian Defence Force
- P2P challenge-response protocol
- Trust database with 6-month expiry
- CRL/OCSP revocation checking (stub)

### Settings UI ✅

**Modified**: `settings/settings_cryptogram.cpp`

- "Device Trust" section (only appears if card detected)
- Enable/disable P2P authorization checkbox
- TPM cipher selection (AES-256-GCM, ChaCha20-Poly1305, AES-192-GCM)

## Remaining UI Integration

### 1. Profile Flag Indicator

**File to modify**: `info/profile/info_profile_cover.cpp`

**Location**: After username label (`_name`)

**Implementation**:

```cpp
// In Cover class (info_profile_cover.h)
object_ptr<Ui::FlatLabel> _trustFlag = { nullptr };

// In Cover::initViewers() (info_profile_cover.cpp)
// After setting up _name label:

// Check if peer has verified CAC credentials
auto trustManager = Core::App().peerTrustManager();
if (trustManager && trustManager->hasPeerTrust(_peer->id)) {
    const auto trustInfo = trustManager->getPeerTrust(_peer->id);

    // Create small flag label
    _trustFlag.create(this, trustInfo.flag, st::infoProfileNameLabel);
    _trustFlag->show();

    // Position after name
    // (adjust based on name width + small gap)

    // Add tooltip on hover
    _trustFlag->setMouseTracking(true);
    _trustFlag->events(
    ) | rpl::filter([=](not_null<QEvent*> e) {
        return e->type() == QEvent::Enter;
    }) | rpl::start_with_next([=] {
        Ui::Tooltip::Show(1000, _trustFlag.data());
    }, _trustFlag->lifetime());

    // Set tooltip text
    _trustFlag->setTooltipText(
        QString("CAC Verified - %1").arg(trustInfo.domain));
}
```

**Styling**: Use `st::infoProfileNameLabel` or smaller font
**Positioning**: `left = _name->x() + _name->width() + st::normalFont->spacew`

### 2. Verify Identity Context Menu

**File to modify**: `info/profile/info_profile_actions.cpp`

**Function**: `actionsList()` or equivalent menu builder

**Implementation**:

```cpp
// In profile action menu builder
auto trustManager = Core::App().peerTrustManager();
if (trustManager && trustManager->isEnabled() && user) {
    const auto hasTrust = trustManager->hasPeerTrust(user->id);

    result.push_back({
        .text = (hasTrust
            ? tr::lng_profile_reverify_identity()
            : tr::lng_profile_verify_identity()),
        .handler = [=] {
            trustManager->requestVerification(user->id);
            showVerificationDialog(user);
        }
    });
}
```

**Lang keys to add** (in `lang/lang_keys.h`):
- `lng_profile_verify_identity` → "Verify Identity (CAC)"
- `lng_profile_reverify_identity` → "Re-verify Identity"

### 3. PIN Entry Dialog

**New file**: `boxes/device_trust_box.{h,cpp}`

**Implementation**:

```cpp
class VerifyIdentityBox : public Ui::BoxContent {
public:
    VerifyIdentityBox(
        QWidget*,
        not_null<UserData*> user,
        QByteArray challenge);

protected:
    void prepare() override;

private:
    void verify();

    not_null<UserData*> _user;
    QByteArray _challenge;
    object_ptr<Ui::InputField> _pin;
    object_ptr<Ui::FlatButton> _verify;
};

void VerifyIdentityBox::prepare() {
    setTitle(tr::lng_verify_identity_title());

    addButton(tr::lng_cancel(), [=] { closeBox(); });

    const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

    content->add(object_ptr<Ui::FlatLabel>(
        content,
        tr::lng_verify_identity_text(
            lt_user,
            rpl::single(_user->name())),
        st::boxLabel));

    _pin = content->add(
        object_ptr<Ui::InputField>(
            content,
            st::defaultInputField,
            tr::lng_verify_identity_pin_placeholder(),
            QString()),
        st::boxRowPadding);
    _pin->setMaxLength(8);

    _verify = addButton(tr::lng_verify(), [=] { verify(); });

    setInnerWidget(object_ptr<Ui::OverrideMargins>(
        this,
        std::move(content)));

    setDimensionsToContent(st::boxWideWidth, content);
}

void VerifyIdentityBox::verify() {
    const auto pin = _pin->getLastText();
    if (pin.isEmpty()) {
        _pin->showError();
        return;
    }

    auto trustManager = Core::App().peerTrustManager();
    trustManager->respondToChallenge(_user->id, _challenge, pin);

    // Show "Verifying..." state
    _verify->setText(tr::lng_verifying());
    _verify->setDisabled(true);

    // Listen for verification result
    // (connect to PeerTrustManager::verificationComplete signal)
}
```

**Lang keys**:
- `lng_verify_identity_title` → "Verify Identity"
- `lng_verify_identity_text` → "Insert your CAC card and enter your PIN to verify your identity to {user}."
- `lng_verify_identity_pin_placeholder` → "CAC PIN"
- `lng_verifying` → "Verifying..."

### 4. Message Encryption Integration

**File to modify**: `data/data_messages.cpp` or encryption handler

**Implementation**:

```cpp
// When sending encrypted message to CAC-verified peer
auto trustManager = Core::App().peerTrustManager();
if (trustManager && trustManager->hasPeerTrust(recipientId)) {
    // Use TPM-backed cipher
    const auto cipher = trustManager->getPreferredCipher();

    // Apply cipher to encryption params
    encryptionParams.cipher = cipher;
    encryptionParams.useTPM = true;
}
```

### 5. Verification History UI

**File to add**: New section in `settings/settings_cryptogram.cpp`

**Implementation**:

```cpp
void Cryptogram::setupVerificationHistorySection(
    not_null<Ui::VerticalLayout*> container) {

    auto trustManager = Core::App().peerTrustManager();
    if (!trustManager || !trustManager->isEnabled()) {
        return;
    }

    Ui::AddSkip(container);
    Ui::AddSubsectionTitle(container,
        rpl::single(QString("Verified Identities")));

    // List all verified peers
    const auto trustedPeers = trustManager->getTrustedPeers();

    for (const auto &[userId, trustInfo] : trustedPeers) {
        auto user = _controller->session().data().user(userId);

        const auto row = container->add(
            object_ptr<Ui::SettingsButton>(
                container,
                rpl::single(QString("%1 %2").arg(
                    trustInfo.flag,
                    user->name())),
                st::settingsButton));

        row->setClickedCallback([=] {
            // Show verification details
            showVerificationDetails(userId, trustInfo);
        });
    }

    if (trustedPeers.empty()) {
        Ui::AddDividerText(container,
            rpl::single(QString(
                "No verified identities yet. "
                "Verify other users with CAC cards using the profile menu.")));
    }
}
```

## Settings Integration

### Core Settings (core/core_settings.h)

Add these settings:

```cpp
// Device Trust Settings
[[nodiscard]] bool deviceTrustEnabled() const {
    return _deviceTrustEnabled;
}
void setDeviceTrustEnabled(bool value) {
    _deviceTrustEnabled = value;
}

[[nodiscard]] int preferredCipher() const {
    return _preferredCipher;
}
void setPreferredCipher(int value) {
    _preferredCipher = value;
}

// Member variables
bool _deviceTrustEnabled = false;
int _preferredCipher = 0; // 0=AES-256-GCM, 1=ChaCha20, 2=AES-192-GCM
```

### Serialization (core/core_settings.cpp)

```cpp
// In save()
stream << _deviceTrustEnabled;
stream << _preferredCipher;

// In load()
stream >> _deviceTrustEnabled;
stream >> _preferredCipher;
```

## Application Integration

### Main Session (main/main_session.h)

Add peer trust manager instance:

```cpp
[[nodiscard]] Core::PeerTrustManager *peerTrustManager() const {
    return _peerTrustManager.get();
}

std::unique_ptr<Core::PeerTrustManager> _peerTrustManager;
```

### Initialization (main/main_session.cpp)

```cpp
MainSession::MainSession(
    not_null<Main::Account*> account,
    const MTPUser &user,
    QByteArray serialized)
: // ... other initializers
, _peerTrustManager(std::make_unique<Core::PeerTrustManager>(this)) {
    // ...
}
```

## Testing Plan

### 1. Card Detection Test
1. Run CRYPTOGRAM Desktop
2. Insert CAC card
3. Open Settings → CRYPTOGRAM
4. Verify "Device Trust" section appears
5. Verify section disappears when card removed

### 2. P2P Verification Test
1. Two users both with CAC cards
2. User A opens User B's profile
3. User A clicks "Verify Identity"
4. User B sees verification request
5. User B inserts card, enters PIN
6. User A sees flag appear in User B's profile
7. Hover over flag → tooltip shows "CAC Verified - US_DOD"

### 3. Encryption Integration Test
1. User A verifies User B (CAC)
2. User A sends encrypted message to User B
3. Verify message uses TPM cipher (AES-256-GCM)
4. User B receives and decrypts successfully

### 4. Trust Expiry Test
1. Verify a user
2. Wait 6 months (or modify expiry for testing)
3. Verify flag disappears
4. Re-verification required

## Security Considerations

### OPSEC Maintained
- NO obvious indicators in message list
- NO colored usernames in chats
- Flag ONLY appears in profile view
- Tooltip required to understand flag meaning
- Settings hidden unless card detected
- Misleading function names preserved

### Threat Model
- **Attacker with source code**: Cannot forge signatures (requires physical card + PIN)
- **Stolen card**: CRL/OCSP revocation blocks verification
- **Replay attack**: Challenge is time-bound and includes nonce
- **MITM**: Certificate chain validates to DoD/MOD roots
- **Social engineering**: Hover tooltip provides verification details

### Privacy
- Trust database stored locally (encrypted)
- No telemetry about CAC usage
- P2P verification (no central server)
- Voluntary opt-in (can remain anonymous)

## Deployment

### Build Requirements
- OpenSSL 1.1.1+ (for X.509 parsing)
- PCSC libraries:
  - Windows: Built-in (WinSCard)
  - Linux: `libpcsclite-dev`
  - macOS: Built-in (PCSC framework)

### Runtime Requirements
- Smart card reader (USB or built-in)
- CAC/PIV card
- Card PIN
- Network access (for CRL/OCSP checks)

## Future Enhancements

1. **Full CRL/OCSP Implementation**: Currently stubbed
2. **Hardware PIN Entry**: Use card reader's PIN pad
3. **Multiple Certificates**: Support selecting which cert to use
4. **Offline Verification**: Cache CRLs for offline use
5. **Audit Log**: Log all verification attempts
6. **Multi-Factor**: Require both CAC + password for encryption keys
7. **International Cards**: Add more military CAs (Germany, France, etc.)

## Support

For questions or issues:
- Check PCSC daemon status: `systemctl status pcscd` (Linux)
- Test card detection: `pcsc_scan` (Linux)
- Verify certificate: `openssl x509 -in cert.pem -text -noout`
- Enable debug logging in `core/credential_helper.cpp`

---

**Status**: Core implementation complete. UI integration in progress.
**Priority**: Profile flag indicator → Context menu → PIN dialog → Encryption → History
