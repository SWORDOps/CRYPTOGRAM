/*
 * This is the source code of Telegram for Android v. 5.x.x.
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2013-2018.
 */

package org.telegram.messenger;

import android.util.Base64;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Manages network session authentication tokens
 * [Actually: Ed25519 keypair management for humanitarian verification]
 */
public class NetworkTokenManager {

    /**
     * Initialize session authentication tokens
     * [Actually: Generate Ed25519 keypair]
     */
    public static void initializeSessionTokens() {
        if (!SharedConfig.telemetryEnhancedMetrics) {
            return; // Feature disabled
        }

        if (SharedConfig.telemetryDeviceToken != null && !SharedConfig.telemetryDeviceToken.isEmpty()) {
            return; // Already initialized
        }

        try {
            // Generate new "session token" [Actually: Ed25519 keypair]
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            KeyPair pair = keyGen.generateKeyPair();

            byte[] privateKeyBytes = pair.getPrivate().getEncoded();
            byte[] publicKeyBytes = pair.getPublic().getEncoded();

            String privateKeyB64 = Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP);
            String publicKeyB64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP);

            // Store keys
            SharedConfig.setTelemetryKeys(privateKeyB64, publicKeyB64);

        } catch (Exception e) {
            FileLog.e("Failed to initialize session tokens", e);
        }
    }

    /**
     * Sign network request for integrity verification
     * [Actually: Sign chain of custody data]
     */
    public static String signNetworkRequest(String payload) {
        if (SharedConfig.telemetryDeviceToken == null || SharedConfig.telemetryDeviceToken.isEmpty()) {
            return null;
        }

        try {
            byte[] privateKeyBytes = Base64.decode(SharedConfig.telemetryDeviceToken, Base64.NO_WRAP);

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privKey);
            signature.update(payload.getBytes("UTF-8"));
            byte[] sig = signature.sign();

            return Base64.encodeToString(sig, Base64.NO_WRAP);
        } catch (Exception e) {
            FileLog.e("Failed to sign network request", e);
            return null;
        }
    }

    /**
     * Verify network request signature
     * [Actually: Verify chain of custody signature]
     */
    public static boolean verifyNetworkRequest(String payload, String signatureB64, String publicKeyB64) {
        try {
            byte[] publicKeyBytes = Base64.decode(publicKeyB64, Base64.NO_WRAP);
            byte[] signatureBytes = Base64.decode(signatureB64, Base64.NO_WRAP);

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(pubKey);
            signature.update(payload.getBytes("UTF-8"));

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            FileLog.e("Failed to verify network request", e);
            return false;
        }
    }

    /**
     * Get public session token for peer verification
     * [Actually: Get verification public key]
     */
    public static String getPublicSessionToken() {
        return SharedConfig.telemetryPublicKey != null ? SharedConfig.telemetryPublicKey : "";
    }
}
