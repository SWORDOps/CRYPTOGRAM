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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
        if (!SharedConfig.cryptogramDoubleRatchet) {
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
                }
                // Desktop parity: the first message goes out as PLAINTEXT
                // with the key bundle attached as an invisible entity
                // (attachKeyBundleIfNeeded in the send path). The old
                // "🔐🧩 + base64" marker message rendered as garbage on
                // desktop clients.
                return message;
            }

            // Encrypt message
            byte[] ciphertext = DoubleRatchet.INSTANCE.encrypt(userId, message);

            if (ciphertext == null) {
                Log.e(TAG, "Encryption returned null");
                return message;
            }

            // Frame as a desktop message envelope (zero-width, desktop
            // alphabet) — this is what desktop unwrapEncryptedText parses.
            String result = DesktopBundleTransport.encodeDesktopMessageEnvelope(ciphertext);

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
        if (!SharedConfig.cryptogramMLS) {
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
        } else if (DesktopBundleTransport.isDesktopEnvelope(message)) {
            return decryptDesktopEnvelope(accountInstance, message, fromId);
        }

        // Not encrypted
        return message;
    }

    /**
     * Decrypt a desktop-framed message envelope (zero-width marker +
     * desktop alphabet) — the format desktop CRYPTOGRAM clients send.
     */
    private static String decryptDesktopEnvelope(int accountInstance, String message, long userId) {
        try {
            byte[] envelope = DesktopBundleTransport.decodeDesktopMessageEnvelope(message);
            if (envelope == null) {
                return message;
            }
            String plaintext = DoubleRatchet.INSTANCE.decrypt(userId, envelope);
            if (plaintext == null) {
                Log.e(TAG, "Desktop envelope decryption returned null for user " + userId);
                bootstrapState.put(userId, BOOTSTRAP_FAILED);
                return "[🔐 Encrypted message cannot be decrypted yet]";
            }
            Log.d(TAG, "Decrypted desktop envelope from user " + userId);
            bootstrapState.put(userId, BOOTSTRAP_READY);
            return plaintext;
        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt desktop envelope", e);
            bootstrapState.put(userId, BOOTSTRAP_FAILED);
            return "[🔐 Encrypted message cannot be decrypted yet]";
        }
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
               message.startsWith(MARKER_DR_BOOTSTRAP + " ") ||
               DesktopBundleTransport.isDesktopEnvelope(message);
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
        } else if (DesktopBundleTransport.isDesktopEnvelope(message)) {
            return "Double Ratchet (desktop)";
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
            return SharedConfig.cryptogramMLS;
        } else {
            // For 1-on-1, require both local toggle and remote capability.
            return SharedConfig.cryptogramDoubleRatchet
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

    // ------------------------------------------------------------------
    // Desktop key-bundle transport (desktop <-> Android interop)
    //
    // Mirrors Data::SignalProtocol::attachKeyBundleIfNeeded /
    // processIncomingKeyBundle: the local bundle is advertised inside
    // outgoing messages as an invisible zero-width payload covered by a
    // messageEntityUnknown(0, len) entity (DesktopBundleTransport).
    // ------------------------------------------------------------------

    /**
     * Attach the local Double Ratchet key bundle to an outgoing 1-on-1 message
     * when the peer has no session yet (desktop attachKeyBundleIfNeeded
     * semantics): the bundle is zero-width encoded, PREPENDED to the message
     * text and covered by a messageEntityUnknown(0, len) entity appended to
     * {@param entities} (existing entity offsets are shifted accordingly).
     * Must be called AFTER {@link #encryptOutgoingMessage}.
     *
     * @param entities mutable outgoing entity list; must not be null (callers
     *                 pass an empty list when no user entities exist)
     * @return the message text with the invisible payload prepended, or the
     *         original text unchanged when no bundle was attached
     */
    public static String attachKeyBundleIfNeeded(int accountInstance, String message, long peerId, ArrayList<TLRPC.MessageEntity> entities) {
        if (message == null || message.isEmpty() || entities == null) {
            return message;
        }
        // 1-on-1 chats only, matching the desktop implementation.
        if (DialogObject.isChatDialog(peerId)) {
            return message;
        }
        if (!SharedConfig.cryptogramDoubleRatchet || !EnhancedPrivacy.INSTANCE.isCryptogramUser(peerId)) {
            return message;
        }
        if (message.startsWith(MARKER_DR_BOOTSTRAP)) {
            // Legacy Android bootstrap already carries the bundle in the marker
            // format — do not double-attach on top of it.
            return message;
        }
        // Desktop parity: advertise the bundle only until a session exists.
        if (DoubleRatchet.INSTANCE.hasSession(peerId)) {
            return message;
        }
        try {
            // The native layer emits the desktop transport layout after the
            // CryptogramWrapper.cpp refactor; fromNativeBundle converts the
            // legacy wrapper if it is still in place.
            byte[] payload = DesktopBundleTransport.fromNativeBundle(DoubleRatchet.INSTANCE.generateKeyBundle());
            if (payload == null || payload.length == 0) {
                Log.e(TAG, "Failed to generate desktop-format key bundle for user " + peerId);
                return message;
            }
            String zwPayload = DesktopBundleTransport.zwEncode(payload);
            TLRPC.TL_messageEntityUnknown bundleEntity = DesktopBundleTransport.buildOutgoingEntity(payload);
            // Mutate the entity list defensively: restore offsets if the list
            // rejects mutation so we never leave shifted entities behind.
            int[] oldOffsets = new int[entities.size()];
            for (int i = 0; i < entities.size(); i++) {
                oldOffsets[i] = entities.get(i).offset;
            }
            try {
                for (int i = 0; i < entities.size(); i++) {
                    entities.get(i).offset += zwPayload.length();
                }
                entities.add(bundleEntity);
            } catch (RuntimeException e) {
                for (int i = 0; i < oldOffsets.length && i < entities.size(); i++) {
                    entities.get(i).offset = oldOffsets[i];
                }
                throw e;
            }
            bootstrapState.put(peerId, BOOTSTRAP_BUNDLE_SENT);
            Log.d(TAG, "Attached desktop key bundle for user " + peerId
                + " (" + payload.length + " bytes, " + zwPayload.length() + " zw chars)");
            return zwPayload + message;
        } catch (Exception e) {
            Log.e(TAG, "Failed to attach key bundle", e);
            return message;
        }
    }

    /**
     * Consume desktop-style key bundles from an incoming message BEFORE the
     * marker-based decryption path (desktop extractAndStripBundles +
     * processIncomingKeyBundle semantics): messageEntityUnknown entities
     * covering zero-width bundle payloads are decoded, fed into the
     * session-establishment path and stripped from {@param entities} and from
     * the returned text.
     *
     * @return the message text with consumed payloads removed; when the
     *         message carried nothing but a bundle, a status placeholder
     */
    public static String extractIncomingBundles(int accountInstance, String messageText, ArrayList<TLRPC.MessageEntity> entities, long peerId, long fromId) {
        if (messageText == null || messageText.isEmpty() || entities == null || entities.isEmpty()) {
            return messageText;
        }
        // 1-on-1 chats only, matching the desktop implementation.
        if (DialogObject.isChatDialog(peerId) || !SharedConfig.cryptogramDoubleRatchet) {
            return messageText;
        }
        long userId = fromId != 0 ? fromId : peerId;
        if (userId == 0) {
            return messageText;
        }
        try {
            ArrayList<int[]> consumed = new ArrayList<>();
            List<byte[]> bundles = DesktopBundleTransport.extractBundles(entities, messageText, consumed);
            if (bundles.isEmpty()) {
                return messageText;
            }
            boolean initialized = false;
            for (byte[] bundle : bundles) {
                if (initializeFromDesktopBundle(userId, bundle)) {
                    initialized = true;
                }
            }
            if (initialized) {
                bootstrapState.put(userId, BOOTSTRAP_BUNDLE_RECEIVED);
                // No echo is requested here: desktop establishes sessions
                // lazily and our own bundle rides the next outgoing message
                // via attachKeyBundleIfNeeded while we still lack a session.
            }
            String stripped = stripRanges(messageText, consumed);
            if (stripped.trim().isEmpty()) {
                // The message was nothing but an invisible key bundle.
                return initialized
                    ? "[🔐 Key exchange completed. Send one more message to finalize secure session.]"
                    : "[🔐 Key exchange failed]";
            }
            return stripped;
        } catch (Exception e) {
            Log.e(TAG, "Failed to extract incoming key bundles", e);
            return messageText;
        }
    }

    /**
     * Feed a desktop transport bundle into the session-establishment path.
     * The refactored native layer consumes the desktop layout directly; the
     * legacy re-wrap is a fallback for older native builds.
     */
    private static boolean initializeFromDesktopBundle(long userId, byte[] desktopBundle) {
        if (DoubleRatchet.INSTANCE.initializeWithRemoteBundle(userId, desktopBundle)) {
            return true;
        }
        // TODO(cryptogram): drop the legacy fallback once CryptogramWrapper.cpp
        // consumes the desktop transport natively.
        byte[] legacy = DesktopBundleTransport.toLegacyNativeBundle(desktopBundle);
        return legacy != null && DoubleRatchet.INSTANCE.initializeWithRemoteBundle(userId, legacy);
    }

    /**
     * Remove the consumed [offset, length) ranges (invisible bundle payloads)
     * from the message text.
     */
    private static String stripRanges(String text, ArrayList<int[]> ranges) {
        if (ranges.isEmpty()) {
            return text;
        }
        Collections.sort(ranges, (a, b) -> a[0] != b[0] ? Integer.compare(a[0], b[0]) : Integer.compare(a[1], b[1]));
        StringBuilder out = new StringBuilder(text.length());
        int pos = 0;
        for (int i = 0; i < ranges.size(); i++) {
            int[] range = ranges.get(i);
            if (range[0] < pos || range[0] + range[1] > text.length()) {
                continue;
            }
            out.append(text, pos, range[0]);
            pos = range[0] + range[1];
        }
        out.append(text, pos, text.length());
        return out.toString();
    }
}
