/**
 * CRYPTOGRAM Native Library Interface
 *
 * Main entry point for CRYPTOGRAM native functionality.
 * Provides version info and initialization.
 */
package org.telegram.messenger.cryptogram

import android.util.Log

object CryptogramNative {
    private const val TAG = "CryptogramNative"

    private var initialized = false

    init {
        try {
            System.loadLibrary("cryptogram")
            initialized = true
            Log.i(TAG, "CRYPTOGRAM native library loaded successfully")
            Log.i(TAG, "Version: ${getVersion()}")
        } catch (e: UnsatisfiedLinkError) {
            initialized = false
            Log.e(TAG, "Failed to load CRYPTOGRAM native library", e)
            Log.e(TAG, "CRYPTOGRAM features will not be available")
        }
    }

    // Native method declarations
    private external fun nativeGetVersion(): String

    /**
     * Check if native library is loaded
     *
     * @return true if library loaded successfully
     */
    fun isInitialized(): Boolean = initialized

    /**
     * Get CRYPTOGRAM native library version
     *
     * @return Version string
     */
    fun getVersion(): String {
        return try {
            if (initialized) {
                nativeGetVersion()
            } else {
                "Not initialized"
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get version", e)
            "Error"
        }
    }

    /**
     * Get feature availability status
     *
     * @return Map of feature names to availability
     */
    fun getFeatureStatus(): Map<String, Boolean> {
        return mapOf(
            "Native Library" to initialized,
            "Double Ratchet" to (initialized && checkDoubleRatchet()),
            "MLS Protocol" to (initialized && checkMLS()),
            "Enhanced Privacy" to initialized
        )
    }

    private fun checkDoubleRatchet(): Boolean {
        return try {
            DoubleRatchet.getState(0) != null
        } catch (e: Exception) {
            false
        }
    }

    private fun checkMLS(): Boolean {
        return try {
            // MLS tree height calculation should work
            MLSProtocol.getTreeHeight(100) > 0
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Log all feature status (for debugging)
     */
    fun logFeatureStatus() {
        Log.i(TAG, "=== CRYPTOGRAM Feature Status ===")
        getFeatureStatus().forEach { (feature, available) ->
            val status = if (available) "✓" else "✗"
            Log.i(TAG, "$status $feature")
        }
        Log.i(TAG, "================================")
    }
}
