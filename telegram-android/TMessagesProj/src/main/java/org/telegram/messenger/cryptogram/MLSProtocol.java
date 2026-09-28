package org.telegram.messenger.cryptogram;

public final class MLSProtocol {
    public static final MLSProtocol INSTANCE = new MLSProtocol();

    private MLSProtocol() {
    }

    public byte[] generateKeyPackage() {
        if (!CryptogramNative.INSTANCE.isLoaded()) {
            return null;
        }
        return nativeGenerateKeyPackage();
    }

    public long processWelcome(byte[] welcomeData) {
        if (!CryptogramNative.INSTANCE.isLoaded() || welcomeData == null) {
            return 0;
        }
        return nativeProcessWelcome(welcomeData);
    }

    public byte[] commitGroupChanges(long groupId) {
        if (!CryptogramNative.INSTANCE.isLoaded()) {
            return null;
        }
        return nativeCommitGroupChanges(groupId);
    }

    public boolean createGroup(long groupId, long[] memberIds) {
        return CryptogramNative.INSTANCE.isLoaded() && memberIds != null && nativeCreateGroup(groupId, memberIds);
    }

    public byte[] encryptGroupMessage(long groupId, String plaintext) {
        if (!CryptogramNative.INSTANCE.isLoaded() || plaintext == null) {
            return null;
        }
        return nativeEncryptGroupMessage(groupId, plaintext);
    }

    public String decryptGroupMessage(long groupId, byte[] ciphertext) {
        if (!CryptogramNative.INSTANCE.isLoaded() || ciphertext == null) {
            return null;
        }
        return nativeDecryptGroupMessage(groupId, ciphertext);
    }

    public boolean addMember(long groupId, long userId) {
        return CryptogramNative.INSTANCE.isLoaded() && nativeAddMember(groupId, userId);
    }

    public boolean removeMember(long groupId, long userId) {
        return CryptogramNative.INSTANCE.isLoaded() && nativeRemoveMember(groupId, userId);
    }

    private native byte[] nativeGenerateKeyPackage();
    private native long nativeProcessWelcome(byte[] welcomeData);
    private native byte[] nativeCommitGroupChanges(long groupId);
    private native boolean nativeCreateGroup(long groupId, long[] memberIds);
    private native byte[] nativeEncryptGroupMessage(long groupId, String plaintext);
    private native String nativeDecryptGroupMessage(long groupId, byte[] ciphertext);
    private native boolean nativeAddMember(long groupId, long userId);
    private native boolean nativeRemoveMember(long groupId, long userId);
}
