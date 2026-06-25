package org.telegram.messenger.cryptogram;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class TSMProvider {
    private static final String TAG = "TSMProvider";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    public static byte[] generateSignalIdentityKeyPair() {
        return generateKeyPair("signal_identity_key");
    }

    public static byte[] generateSignalPreKey() {
        return generateKeyPair("signal_pre_key_" + System.currentTimeMillis());
    }

    public static byte[] generateSignalOneTimeKey() {
        return generateKeyPair("signal_otp_key_" + System.currentTimeMillis());
    }

    public static byte[] signSignalMessage(String alias, byte[] data) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            if (privateKeyEntry == null) {
                Log.e(TAG, "Private key not found for alias: " + alias);
                return null;
            }

            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(privateKeyEntry.getPrivateKey());
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            Log.e(TAG, "Signing failed", e);
            return null;
        }
    }

    private static byte[] generateKeyPair(String alias) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(false)
                    .build());

            KeyPair kp = kpg.generateKeyPair();
            return kp.getPublic().getEncoded();
        } catch (Exception e) {
            Log.e(TAG, "Key generation failed", e);
            return null;
        }
    }
}
