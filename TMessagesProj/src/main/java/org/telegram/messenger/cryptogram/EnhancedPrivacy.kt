/**
 * CRYPTOGRAM Enhanced Privacy Features
 *
 * Provides privacy enhancements including:
 * - CRYPTOGRAM user detection (green name identification)
 * - Privacy status tracking
 * - Metadata protection
 */
package org.telegram.messenger.cryptogram

import android.util.Log

object EnhancedPrivacy {
    private const val TAG = "EnhancedPrivacy"

    init {
        try {
            System.loadLibrary("cryptogram")
            Log.d(TAG, "CRYPTOGRAM native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load CRYPTOGRAM native library", e)
        }
    }

    // Native method declarations
    private external fun nativeIsCryptogramUser(userId: Long): Boolean

    /**
     * Check if a user is a CRYPTOGRAM user
     *
     * CRYPTOGRAM users have enhanced privacy features enabled and
     * their names are displayed in green in the UI.
     *
     * @param userId Telegram user ID
     * @return true if user has CRYPTOGRAM enabled
     */
    fun isCryptogramUser(userId: Long): Boolean {
        return try {
            nativeIsCryptogramUser(userId)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check CRYPTOGRAM status for user $userId", e)
            false
        }
    }

    /**
     * Get privacy status description for UI
     *
     * @param userId Telegram user ID
     * @return Privacy status string
     */
    fun getPrivacyStatus(userId: Long): String {
        return if (isCryptogramUser(userId)) {
            "🔐 CRYPTOGRAM User - Enhanced Privacy"
        } else {
            "Standard Privacy"
        }
    }

    /**
     * Should use Double Ratchet with this user?
     *
     * @param userId Telegram user ID
     * @return true if Double Ratchet should be used
     */
    fun shouldUseDoubleRatchet(userId: Long): Boolean {
        // Use Double Ratchet if both users are CRYPTOGRAM users
        return isCryptogramUser(userId)
    }

    /**
     * Should use MLS for this group?
     *
     * @param memberIds Group member IDs
     * @return true if MLS should be used
     */
    fun shouldUseMLS(memberIds: LongArray): Boolean {
        // Use MLS if at least 2 CRYPTOGRAM users are in the group
        val cryptogramCount = memberIds.count { isCryptogramUser(it) }
        return cryptogramCount >= 2
    }
}
