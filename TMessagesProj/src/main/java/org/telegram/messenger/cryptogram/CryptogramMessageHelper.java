/*
 * CRYPTOGRAM Message Helper
 * Handles encryption/decryption of messages
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

package org.telegram.messenger.cryptogram;

import android.util.Base64;
import android.util.Log;

import org.telegram.messenger.DialogObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.UserConfig;
import org.telegram.tgnet.TLRPC;

/**
 * Helper class for CRYPTOGRAM message encryption/decryption
 *
 * Handles:
 * - Double Ratchet (Signal Protocol) for 1-on-1 chats
 * - MLS Protocol for group chats
 * - Message format markers
 * - User compatibility checks
 */
public class CryptogramMessageHelper {

    private static final String TAG = "CryptogramMessageHelper";

    // Message format markers
    public static final String MARKER_DOUBLE_RATCHET = "🔐";
    public static final String MARKER_MLS = "🔐📦";

    /**
     * Encrypt an outgoing message if CRYPTOGRAM is enabled
     *
     * @param accountInstance Account instance for accessing user data
     * @param message Original message text
     * @param peerId Peer ID (user or chat)
     * @return Encrypted message with marker, or original message if encryption disabled/failed
     */
    public static String encryptOutgoingMessage(int accountInstance, String message, long peerId) {
        if (message == null || message.isEmpty()) {
            return message;
        }

        // Check if this is a group or channel
        boolean isGroup = DialogObject.isChatDialog(peerId);

        if (isGroup) {
            return encryptGroupMessage(accountInstance, message, peerId);
        } else {
            return encrypt1on1Message(accountInstance, message, peerId);
        }
    }

    /**
     * Encrypt a 1-on-1 message using Double Ratchet (Signal Protocol)
     */
    private static String encrypt1on1Message(int accountInstance, String message, long userId) {
        // Check if Double Ratchet is enabled
        if (!SharedConfig.cryptogramDoubleRatchetEnabled) {
            return message;
        }

        try {
            // Initialize session if needed
            if (!DoubleRatchet.INSTANCE.hasSession(userId)) {
                Log.d(TAG, "Initializing Double Ratchet session for user " + userId);
                if (!DoubleRatchet.INSTANCE.initializeSession(userId)) {
                    Log.e(TAG, "Failed to initialize Double Ratchet session");
                    return message;
                }
            }

            // Encrypt message
            byte[] ciphertext = DoubleRatchet.INSTANCE.encrypt(userId, message);

            if (ciphertext == null) {
                Log.e(TAG, "Encryption returned null");
                return message;
            }

            // Encode as base64 and add marker
            String encoded = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            String result = MARKER_DOUBLE_RATCHET + " " + encoded;

            Log.d(TAG, "Encrypted message for user " + userId + " (" + ciphertext.length + " bytes)");
            return result;

        } catch (Exception e) {
            Log.e(TAG, "Failed to encrypt message", e);
            return message;
        }
    }

    /**
     * Encrypt a group message using MLS Protocol
     */
    private static String encryptGroupMessage(int accountInstance, String message, long groupId) {
        // Check if MLS is enabled
        if (!SharedConfig.cryptogramMLSEnabled) {
            return message;
        }

        try {
            // Encrypt message
            byte[] ciphertext = MLSProtocol.INSTANCE.encryptGroupMessage(groupId, message);

            if (ciphertext == null) {
                Log.e(TAG, "Group encryption returned null");
                return message;
            }

            // Encode as base64 and add marker
            String encoded = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            String result = MARKER_MLS + " " + encoded;

            Log.d(TAG, "Encrypted group message for chat " + groupId + " (" + ciphertext.length + " bytes)");
            return result;

        } catch (Exception e) {
            Log.e(TAG, "Failed to encrypt group message", e);
            return message;
        }
    }

    /**
     * Decrypt an incoming message if it's encrypted
     *
     * @param accountInstance Account instance for accessing user data
     * @param message Incoming message text (may be encrypted)
     * @param peerId Peer ID (user or chat)
     * @param fromId Sender user ID
     * @return Decrypted message, or original message if not encrypted/decryption failed
     */
    public static String decryptIncomingMessage(int accountInstance, String message, long peerId, long fromId) {
        if (message == null || message.isEmpty()) {
            return message;
        }

        // Check for encryption markers
        if (message.startsWith(MARKER_MLS + " ")) {
            return decryptGroupMessage(accountInstance, message, peerId);
        } else if (message.startsWith(MARKER_DOUBLE_RATCHET + " ")) {
            return decrypt1on1Message(accountInstance, message, fromId);
        }

        // Not encrypted
        return message;
    }

    /**
     * Decrypt a 1-on-1 message using Double Ratchet
     */
    private static String decrypt1on1Message(int accountInstance, String message, long userId) {
        try {
            // Remove marker and extract base64
            String base64 = message.substring(MARKER_DOUBLE_RATCHET.length() + 1);
            byte[] ciphertext = Base64.decode(base64, Base64.NO_WRAP);

            // Decrypt
            String plaintext = DoubleRatchet.INSTANCE.decrypt(userId, ciphertext);

            if (plaintext == null) {
                Log.e(TAG, "Decryption returned null");
                return "[🔐 Decryption failed]";
            }

            Log.d(TAG, "Decrypted message from user " + userId);
            return plaintext;

        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt message", e);
            return "[🔐 Decryption failed]";
        }
    }

    /**
     * Decrypt a group message using MLS Protocol
     */
    private static String decryptGroupMessage(int accountInstance, String message, long groupId) {
        try {
            // Remove marker and extract base64
            String base64 = message.substring(MARKER_MLS.length() + 1);
            byte[] ciphertext = Base64.decode(base64, Base64.NO_WRAP);

            // Decrypt
            String plaintext = MLSProtocol.INSTANCE.decryptGroupMessage(groupId, ciphertext);

            if (plaintext == null) {
                Log.e(TAG, "Group decryption returned null");
                return "[🔐 Group decryption failed]";
            }

            Log.d(TAG, "Decrypted group message for chat " + groupId);
            return plaintext;

        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt group message", e);
            return "[🔐 Group decryption failed]";
        }
    }

    /**
     * Check if a message is encrypted
     *
     * @param message Message text
     * @return true if message has encryption marker
     */
    public static boolean isEncryptedMessage(String message) {
        if (message == null) {
            return false;
        }
        return message.startsWith(MARKER_DOUBLE_RATCHET + " ") ||
               message.startsWith(MARKER_MLS + " ");
    }

    /**
     * Get encryption type of a message
     *
     * @param message Message text
     * @return "Double Ratchet", "MLS", or null if not encrypted
     */
    public static String getEncryptionType(String message) {
        if (message == null) {
            return null;
        }
        if (message.startsWith(MARKER_MLS + " ")) {
            return "MLS Protocol";
        } else if (message.startsWith(MARKER_DOUBLE_RATCHET + " ")) {
            return "Double Ratchet";
        }
        return null;
    }

    /**
     * Should we encrypt messages for this peer?
     *
     * @param accountInstance Account instance
     * @param peerId Peer ID
     * @return true if encryption should be used
     */
    public static boolean shouldEncrypt(int accountInstance, long peerId) {
        boolean isGroup = DialogObject.isChatDialog(peerId);

        if (isGroup) {
            // For groups, check if MLS is enabled
            return SharedConfig.cryptogramMLSEnabled;
        } else {
            // For 1-on-1, check if Double Ratchet is enabled
            // Optionally: Also check if other user is a CRYPTOGRAM user
            return SharedConfig.cryptogramDoubleRatchetEnabled;
        }
    }
}
