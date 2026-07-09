import sys
import hashlib
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialDescriptor

class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\n>>> PLEASE TOUCH YOUR YUBIKEY NOW <<<")
        sys.stdout.flush()

try:
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    print(f"Found FIDO device: {dev}")
    client = Fido2Client(dev, "https://cryptogram.local", user_interaction=CliInteraction())
    server = Fido2Server(PublicKeyCredentialRpEntity(id="cryptogram.local", name="CRYPTOGRAM"))

    cred_id_hex = "f9d982c3e36687740ec0e9eb725b847fab2256dd2e12c6ba64b9d2fb37b9d91566ffb77f54f834fdb9caf9630af4d6ff0861bc3e435ddb2ed17e323375514748"
    cred_id = bytes.fromhex(cred_id_hex)
    
    descriptor = PublicKeyCredentialDescriptor(type="public-key", id=cred_id)

    salt = hashlib.sha256(b"cryptogram_cloud_password_salt").digest()
    
    auth_options, state = server.authenticate_begin(
        [descriptor],
        user_verification="discouraged",
        extensions={"hmacGetSecret": {"salt1": salt}}
    )

    print("Requesting deterministic HMAC secret from YubiKey...")
    auth_result = client.get_assertion(auth_options.public_key)
    
    hmac_secret = auth_result.get_response(0).extension_results.get("hmacGetSecret", {}).get("output1")
    
    if hmac_secret:
        print(f"\nSUCCESS! Deterministic YubiKey FIPS Secret: {hmac_secret.hex()}")
    else:
        print("\nFAILURE: YubiKey did not return hmac-secret!")

except Exception as e:
    print(f"Error: {e}")
