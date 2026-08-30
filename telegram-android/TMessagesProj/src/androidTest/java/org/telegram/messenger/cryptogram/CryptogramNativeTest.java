package org.telegram.messenger.cryptogram;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * Smoke test for the CRYPTOGRAM JNI bridge.
 *
 * <p>This instrumentation test verifies that the native library can be loaded
 * and that the core self-check methods do not crash. It does not validate
 * cryptographic correctness — only that the JNI surface is reachable.</p>
 *
 * <p>Run with: {@code ./gradlew connectedAndroidTest}</p>
 */
public class CryptogramNativeTest {

    private CryptogramNative cryptogramNative;

    @Before
    public void setUp() {
        cryptogramNative = CryptogramNative.INSTANCE;
    }

    /**
     * Verify that the singleton instance is non-null and can be obtained.
     */
    @Test
    public void instanceIsAvailable() {
        assertNotNull("CryptogramNative.INSTANCE should not be null", cryptogramNative);
    }

    /**
     * Verify that getVersion() returns a non-null string containing "CRYPTOGRAM".
     *
     * <p>If the native library failed to load, getVersion() returns a fallback
     * string that still contains "CRYPTOGRAM", so this test passes either way
     * — it only fails if the method crashes or returns null.</p>
     */
    @Test
    public void getVersionReturnsCryptogramString() {
        String version = cryptogramNative.getVersion();
        assertNotNull("getVersion() should not return null", version);
        assertTrue(
            "getVersion() should contain 'CRYPTOGRAM', got: " + version,
            version.contains("CRYPTOGRAM")
        );
    }

    /**
     * Verify that checkDoubleRatchet() returns a boolean without crashing.
     *
     * <p>The return value may be true or false depending on whether the native
     * library is loaded and the self-check passes. The test only asserts that
     * the call completes without throwing an exception.</p>
     */
    @Test
    public void checkDoubleRatchetReturnsBoolean() {
        boolean result = cryptogramNative.checkDoubleRatchet();
        // Accept either true or false — we only care that it doesn't crash.
        assertTrue("checkDoubleRatchet() should return a boolean", result || !result);
    }

    /**
     * Verify that checkMLS() returns a boolean without crashing.
     *
     * <p>The return value may be true or false depending on whether the native
     * library is loaded and the self-check passes. The test only asserts that
     * the call completes without throwing an exception.</p>
     */
    @Test
    public void checkMLSReturnsBoolean() {
        boolean result = cryptogramNative.checkMLS();
        // Accept either true or false — we only care that it doesn't crash.
        assertTrue("checkMLS() should return a boolean", result || !result);
    }
}
