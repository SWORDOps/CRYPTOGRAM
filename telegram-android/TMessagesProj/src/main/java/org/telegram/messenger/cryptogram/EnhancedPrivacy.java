package org.telegram.messenger.cryptogram;

public final class EnhancedPrivacy {
    public static final EnhancedPrivacy INSTANCE = new EnhancedPrivacy();

    private EnhancedPrivacy() {
    }

    public boolean isCryptogramUser(long userId) {
        return CryptogramNative.INSTANCE.isLoaded() && nativeIsCryptogramUser(userId);
    }

    private native boolean nativeIsCryptogramUser(long userId);
}
