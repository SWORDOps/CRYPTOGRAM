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
    private external fun nativeCheckDoubleRatchet(): Boolean
    private external fun nativeCheckMLS(): Boolean
    private external fun nativeInitializeStorage(path: String)

    /**
     * Initialize the native library with application storage path.
     *
     * @param filesDir Absolute path to internal app files directory
     */
    fun initialize(filesDir: String) {
        try {
            if (initialized) {
                nativeInitializeStorage(filesDir)
                Log.i(TAG, "Storage initialized at $filesDir")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize storage", e)
        }
    }

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
        val doubleRatchetReady = initialized && checkDoubleRatchet()
        val mlsReady = initialized && checkMLS()
        return mapOf(
            "Native Library" to initialized,
            "Double Ratchet" to doubleRatchetReady,
            "MLS Protocol" to mlsReady,
            "Enhanced Privacy" to initialized
        )
    }

    private fun checkDoubleRatchet(): Boolean {
        return try {
            nativeCheckDoubleRatchet()
        } catch (e: Exception) {
            Log.e(TAG, "Double Ratchet self-test failed", e)
            false
        }
    }

    private fun checkMLS(): Boolean {
        return try {
            nativeCheckMLS()
        } catch (e: Exception) {
            Log.e(TAG, "MLS self-test failed", e)
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
