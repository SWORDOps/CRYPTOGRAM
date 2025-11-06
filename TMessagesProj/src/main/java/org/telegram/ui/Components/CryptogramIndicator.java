/*
 * CRYPTOGRAM Visual Indicators
 * Provides visual feedback for encrypted messages
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

package org.telegram.ui.Components;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ImageSpan;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.R;
import org.telegram.messenger.cryptogram.CryptogramMessageHelper;
import org.telegram.ui.ActionBar.Theme;

/**
 * Helper class for displaying CRYPTOGRAM encryption indicators in UI
 */
public class CryptogramIndicator {

    /**
     * Add a small lock icon to encrypted message text
     *
     * @param text Original message text
     * @param isEncrypted Whether the message is encrypted
     * @return Text with lock icon prepended if encrypted
     */
    public static CharSequence addLockIconToText(CharSequence text, boolean isEncrypted) {
        if (!isEncrypted || text == null) {
            return text;
        }

        // Add small lock emoji before the text
        return "🔒 " + text;
    }

    /**
     * Get encryption status text for chat header
     *
     * @param message Sample message from chat
     * @return Status text like "Double Ratchet Encryption" or null
     */
    public static String getEncryptionStatusText(String message) {
        if (message == null) {
            return null;
        }

        String encryptionType = CryptogramMessageHelper.getEncryptionType(message);
        if (encryptionType != null) {
            return "🔐 " + encryptionType;
        }

        return null;
    }

    /**
     * Get color tint for encrypted chat titles
     *
     * @return Green color for encrypted chats
     */
    public static int getEncryptedChatTitleColor() {
        // Green color to indicate encryption
        return 0xFF4CAF50; // Material Green 500
    }

    /**
     * Check if we should show encryption indicator for this message
     *
     * @param messageText Message text
     * @return true if message is encrypted
     */
    public static boolean shouldShowIndicator(String messageText) {
        return CryptogramMessageHelper.isEncryptedMessage(messageText);
    }

    /**
     * Get short encryption badge text
     *
     * @param messageText Message text
     * @return "DR" for Double Ratchet, "MLS" for MLS, or null
     */
    public static String getEncryptionBadge(String messageText) {
        if (messageText == null) {
            return null;
        }

        if (messageText.startsWith(CryptogramMessageHelper.MARKER_MLS + " ")) {
            return "MLS";
        } else if (messageText.startsWith(CryptogramMessageHelper.MARKER_DOUBLE_RATCHET + " ")) {
            return "DR";
        }

        return null;
    }

    /**
     * Create a small badge drawable for encrypted messages
     *
     * @param badge Badge text ("DR" or "MLS")
     * @return Badge text with styling
     */
    public static String createEncryptionBadge(String badge) {
        if (badge == null) {
            return "";
        }
        // Small badge in square brackets
        return " [" + badge + "]";
    }
}
