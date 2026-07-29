package org.telegram.messenger.cryptogram;

public final class DoubleRatchet {
    public static final DoubleRatchet INSTANCE = new DoubleRatchet();

    private DoubleRatchet() {
    }

    public boolean initializeSession(long userId) {
        return CryptogramNative.INSTANCE.isLoaded() && nativeInitializeSession(userId);
    }

    public byte[] generateKeyBundle() {
        if (!CryptogramNative.INSTANCE.isLoaded()) {
            return null;
        }
        return nativeGenerateKeyBundle();
    }

    public boolean initializeWithRemoteBundle(long userId, byte[] bundle) {
        return CryptogramNative.INSTANCE.isLoaded() && bundle != null && nativeInitializeWithRemoteBundle(userId, bundle);
    }

    public boolean hasSession(long userId) {
        return CryptogramNative.INSTANCE.isLoaded() && nativeHasSession(userId);
    }

    public byte[] encrypt(long userId, String plaintext) {
        if (!CryptogramNative.INSTANCE.isLoaded() || plaintext == null) {
            return null;
        }
        return nativeEncrypt(userId, plaintext);
    }

    public String decrypt(long userId, byte[] ciphertext) {
        if (!CryptogramNative.INSTANCE.isLoaded() || ciphertext == null) {
            return null;
        }
        return nativeDecrypt(userId, ciphertext);
    }

    public boolean rotateSession(long userId) {
        return CryptogramNative.INSTANCE.isLoaded() && nativeRotateSession(userId);
    }

    public String getFingerprint(long userId) {
        if (!CryptogramNative.INSTANCE.isLoaded()) {
            return "UNINITIALIZED";
        }
        return nativeGetFingerprint(userId);
    }

    public String getState(long userId) {
        if (!CryptogramNative.INSTANCE.isLoaded()) {
            return "{\"initialized\": false}";
        }
        return nativeGetState(userId);
    }

    private native boolean nativeInitializeSession(long userId);
    private native byte[] nativeGenerateKeyBundle();
    private native boolean nativeInitializeWithRemoteBundle(long userId, byte[] bundle);
    private native boolean nativeHasSession(long userId);
    private native byte[] nativeEncrypt(long userId, String plaintext);
    private native String nativeDecrypt(long userId, byte[] ciphertext);
    private native boolean nativeRotateSession(long userId);
    private native String nativeGetFingerprint(long userId);
    private native String nativeGetState(long userId);
}
