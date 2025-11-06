/**
 * CRYPTOGRAM MLS Protocol (Message Layer Security)
 *
 * Provides end-to-end encryption for group chats using the MLS Protocol (RFC 9420).
 *
 * Features:
 * - TreeKEM algorithm for efficient key distribution (O(log n))
 * - Forward secrecy for groups
 * - Post-compromise security (self-healing)
 * - Efficient member add/remove operations
 * - Epoch-based ratcheting
 *
 * Usage:
 * ```kotlin
 * val mls = MLSProtocol
 *
 * // Create encrypted group
 * val members = longArrayOf(user1Id, user2Id, user3Id)
 * mls.createGroup(groupId, members)
 *
 * // Encrypt group message
 * val encrypted = mls.encryptGroupMessage(groupId, "Hello group!")
 *
 * // Decrypt group message
 * val plaintext = mls.decryptGroupMessage(groupId, encryptedBytes)
 *
 * // Add member (increments epoch, updates tree)
 * mls.addMember(groupId, newUserId)
 *
 * // Remove member (increments epoch, updates tree)
 * mls.removeMember(groupId, oldUserId)
 * ```
 */
package org.telegram.messenger.cryptogram

import android.util.Log

object MLSProtocol {
    private const val TAG = "MLSProtocol"

    init {
        try {
            System.loadLibrary("cryptogram")
            Log.d(TAG, "CRYPTOGRAM native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load CRYPTOGRAM native library", e)
        }
    }

    // Native method declarations
    private external fun nativeCreateGroup(groupId: Long, memberIds: LongArray): Boolean
    private external fun nativeEncryptGroupMessage(groupId: Long, plaintext: String): ByteArray?
    private external fun nativeDecryptGroupMessage(groupId: Long, ciphertext: ByteArray): String?
    private external fun nativeAddMember(groupId: Long, userId: Long): Boolean
    private external fun nativeRemoveMember(groupId: Long, userId: Long): Boolean

    /**
     * Create an encrypted group using MLS
     *
     * Initializes the TreeKEM ratchet tree with all members and establishes
     * the initial epoch key.
     *
     * @param groupId Telegram group/chat ID
     * @param memberIds Array of member user IDs
     * @return true if group created successfully
     */
    fun createGroup(groupId: Long, memberIds: LongArray): Boolean {
        if (memberIds.isEmpty()) {
            Log.w(TAG, "Cannot create group with no members")
            return false
        }

        return try {
            val result = nativeCreateGroup(groupId, memberIds)
            Log.d(TAG, "Group $groupId created with ${memberIds.size} members: $result")
            result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create group $groupId", e)
            false
        }
    }

    /**
     * Encrypt a message for a group
     *
     * Uses the current epoch key to encrypt the message. All group members
     * in the current epoch can decrypt.
     *
     * @param groupId Telegram group/chat ID
     * @param plaintext Message to encrypt
     * @return Encrypted ciphertext, or null on failure
     */
    fun encryptGroupMessage(groupId: Long, plaintext: String): ByteArray? {
        if (plaintext.isEmpty()) {
            Log.w(TAG, "Cannot encrypt empty message")
            return null
        }

        return try {
            val ciphertext = nativeEncryptGroupMessage(groupId, plaintext)
            if (ciphertext != null) {
                Log.d(TAG, "Encrypted group message for $groupId (${ciphertext.size} bytes)")
            } else {
                Log.e(TAG, "Group encryption returned null for $groupId")
            }
            ciphertext
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt group message for $groupId", e)
            null
        }
    }

    /**
     * Decrypt a message from a group
     *
     * Uses the current epoch key to decrypt the message.
     *
     * @param groupId Telegram group/chat ID
     * @param ciphertext Encrypted message
     * @return Decrypted plaintext, or null on failure
     */
    fun decryptGroupMessage(groupId: Long, ciphertext: ByteArray): String? {
        if (ciphertext.isEmpty()) {
            Log.w(TAG, "Cannot decrypt empty ciphertext")
            return null
        }

        return try {
            val plaintext = nativeDecryptGroupMessage(groupId, ciphertext)
            if (plaintext != null) {
                Log.d(TAG, "Decrypted group message for $groupId")
            } else {
                Log.e(TAG, "Group decryption returned null for $groupId")
            }
            plaintext
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt group message for $groupId", e)
            null
        }
    }

    /**
     * Add a member to an MLS group
     *
     * Increments the epoch, updates the TreeKEM tree, and distributes new keys.
     * All members receive the updated tree and new epoch key.
     *
     * @param groupId Telegram group/chat ID
     * @param userId User ID to add
     * @return true if member added successfully
     */
    fun addMember(groupId: Long, userId: Long): Boolean {
        return try {
            val result = nativeAddMember(groupId, userId)
            if (result) {
                Log.d(TAG, "Added member $userId to group $groupId (epoch incremented)")
            } else {
                Log.e(TAG, "Failed to add member $userId to group $groupId")
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add member $userId to group $groupId", e)
            false
        }
    }

    /**
     * Remove a member from an MLS group
     *
     * Increments the epoch, updates the TreeKEM tree, and distributes new keys.
     * The removed member cannot decrypt future messages.
     *
     * @param groupId Telegram group/chat ID
     * @param userId User ID to remove
     * @return true if member removed successfully
     */
    fun removeMember(groupId: Long, userId: Long): Boolean {
        return try {
            val result = nativeRemoveMember(groupId, userId)
            if (result) {
                Log.d(TAG, "Removed member $userId from group $groupId (epoch incremented)")
            } else {
                Log.e(TAG, "Failed to remove member $userId from group $groupId")
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove member $userId from group $groupId", e)
            false
        }
    }

    /**
     * Get estimated tree height for a group size
     *
     * TreeKEM has O(log n) complexity, so this shows the efficiency.
     *
     * @param memberCount Number of members
     * @return Tree height
     */
    fun getTreeHeight(memberCount: Int): Int {
        if (memberCount <= 0) return 0
        return kotlin.math.ceil(kotlin.math.log2(memberCount.toDouble())).toInt()
    }

    /**
     * Get maximum members for efficient operation
     *
     * MLS can handle thousands of members efficiently.
     *
     * @return Recommended maximum members
     */
    fun getMaxMembers(): Int {
        return 10000 // TreeKEM is efficient even with large groups
    }
}
