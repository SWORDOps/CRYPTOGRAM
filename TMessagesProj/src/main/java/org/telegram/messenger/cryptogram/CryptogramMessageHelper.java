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

import java.util.concurrent.ConcurrentHashMap;

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
    public static final String MARKER_DR_BOOTSTRAP = "🔐🧩";
    private static final ConcurrentHashMap<Long, Boolean> pendingBootstrapEcho = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Long, String> bootstrapState = new ConcurrentHashMap<>();
    private static final String BOOTSTRAP_NONE = "none";
    private static final String BOOTSTRAP_NEEDS_BUNDLE = "needs_bundle";
    private static final String BOOTSTRAP_BUNDLE_SENT = "bundle_sent";
    private static final String BOOTSTRAP_BUNDLE_RECEIVED = "bundle_received";
    private static final String BOOTSTRAP_READY = "ready";
    private static final String BOOTSTRAP_FAILED = "failed";

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
        // Require remote capability before transforming user-visible payload.
        if (!EnhancedPrivacy.INSTANCE.isCryptogramUser(userId)) {
            return message;
        }

        try {
            bootstrapState.put(userId, BOOTSTRAP_NONE);

            // If peer asked for echo bootstrap, prioritize that first.
            if (pendingBootstrapEcho.remove(userId) != null) {
                byte[] bundle = DoubleRatchet.INSTANCE.generateKeyBundle();
                if (bundle != null && bundle.length > 0) {
                    bootstrapState.put(userId, BOOTSTRAP_BUNDLE_SENT);
                    return MARKER_DR_BOOTSTRAP + " " + Base64.encodeToString(bundle, Base64.NO_WRAP);
                }
                bootstrapState.put(userId, BOOTSTRAP_FAILED);
            }

            // Initialize session if needed, otherwise send bootstrap bundle marker.
            if (!DoubleRatchet.INSTANCE.hasSession(userId)) {
                bootstrapState.put(userId, BOOTSTRAP_NEEDS_BUNDLE);
                byte[] bundle = DoubleRatchet.INSTANCE.generateKeyBundle();
                if (bundle != null && bundle.length > 0) {
                    bootstrapState.put(userId, BOOTSTRAP_BUNDLE_SENT);
                    return MARKER_DR_BOOTSTRAP + " " + Base64.encodeToString(bundle, Base64.NO_WRAP);
                }
                bootstrapState.put(userId, BOOTSTRAP_FAILED);
                Log.e(TAG, "No session and failed to generate bootstrap bundle for user " + userId);
                return message;
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
            bootstrapState.put(userId, BOOTSTRAP_READY);
            return result;

        } catch (Exception e) {
            Log.e(TAG, "Failed to encrypt message", e);
            bootstrapState.put(userId, BOOTSTRAP_FAILED);
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
        } else if (message.startsWith(MARKER_DR_BOOTSTRAP + " ")) {
            return decrypt1on1Message(accountInstance, message, fromId);
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
            if (message.startsWith(MARKER_DR_BOOTSTRAP + " ")) {
                String base64Bundle = message.substring(MARKER_DR_BOOTSTRAP.length() + 1);
                byte[] bundle = Base64.decode(base64Bundle, Base64.NO_WRAP);
                boolean initialized = DoubleRatchet.INSTANCE.initializeWithRemoteBundle(userId, bundle);
                if (initialized) {
                    bootstrapState.put(userId, BOOTSTRAP_BUNDLE_RECEIVED);
                    pendingBootstrapEcho.put(userId, true);
                    return "[🔐 Key exchange completed. Send one more message to finalize secure session.]";
                }
                bootstrapState.put(userId, BOOTSTRAP_FAILED);
                return "[🔐 Key exchange failed]";
            }

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
            bootstrapState.put(userId, BOOTSTRAP_READY);
            return plaintext;

        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt message", e);
            bootstrapState.put(userId, BOOTSTRAP_FAILED);
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
               message.startsWith(MARKER_MLS + " ") ||
               message.startsWith(MARKER_DR_BOOTSTRAP + " ");
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
        } else if (message.startsWith(MARKER_DR_BOOTSTRAP + " ")) {
            return "Double Ratchet Bootstrap";
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
            // For 1-on-1, require both local toggle and remote capability.
            return SharedConfig.cryptogramDoubleRatchetEnabled
                && EnhancedPrivacy.INSTANCE.isCryptogramUser(peerId);
        }
    }

    /**
     * Returns current bootstrap/session state for 1:1 Double Ratchet peer setup.
     */
    public static String getBootstrapState(long userId) {
        String state = bootstrapState.get(userId);
        if (state == null) {
            return BOOTSTRAP_NONE;
        }
        return state;
    }
}
