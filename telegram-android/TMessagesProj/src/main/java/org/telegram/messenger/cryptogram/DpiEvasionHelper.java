/*
 * CRYPTOGRAM DPI Evasion Helper
 * Adds padding and randomization to outgoing data to evade Deep Packet Inspection.
 *
 * On Android, full transport-level DPI evasion requires native MTProto modifications,
 * but we can apply application-layer padding to make traffic patterns harder to fingerprint.
 */
package org.telegram.messenger.cryptogram;

import java.security.SecureRandom;
import java.util.Random;

public final class DpiEvasionHelper {

    private static final DpiEvasionHelper INSTANCE = new DpiEvasionHelper();
    private static final Random RNG = new SecureRandom();

    // Padding marker — uses zero-width characters to avoid visual impact
    private static final String PADDING_PREFIX = "\u200b\u200b";

    private DpiEvasionHelper() {}

    public static DpiEvasionHelper getInstance() { return INSTANCE; }

    /**
     * Apply DPI evasion padding to an outgoing message.
     * Adds random-length zero-width character padding to normalize message sizes
     * and prevent traffic analysis based on message length patterns.
     *
     * @param message Original message text
     * @return Padded message, or original if null/empty
     */
    public String applyPadding(String message) {
        if (message == null || message.isEmpty()) {
            return message;
        }
        // Add random padding between 0-256 zero-width spaces
        int paddingLen = RNG.nextInt(256);
        StringBuilder sb = new StringBuilder(message.length() + paddingLen + PADDING_PREFIX.length());
        sb.append(message);
        sb.append(PADDING_PREFIX);
        for (int i = 0; i < paddingLen; i++) {
            sb.append('\u200b'); // Zero-width space
        }
        return sb.toString();
    }

    /**
     * Strip DPI evasion padding from an incoming message.
     * Removes all zero-width characters.
     *
     * @param message Padded message
     * @return Cleaned message, or original if null/empty
     */
    public String stripPadding(String message) {
        if (message == null || message.isEmpty()) {
            return message;
        }
        // Remove all zero-width characters
        return message.replaceAll("[\u200b\u200c\u200d\ufeff]", "");
    }
}
