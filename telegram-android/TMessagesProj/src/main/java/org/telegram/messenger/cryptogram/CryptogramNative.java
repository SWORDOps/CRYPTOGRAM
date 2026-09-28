package org.telegram.messenger.cryptogram;

import android.util.Log;

import org.telegram.messenger.ApplicationLoader;

public final class CryptogramNative {
    public static final CryptogramNative INSTANCE = new CryptogramNative();

    private static final String TAG = "CryptogramNative";
    private static volatile boolean loaded;

    static {
        try {
            System.loadLibrary("cryptogram");
            loaded = true;
        } catch (Throwable e) {
            loaded = false;
            Log.e(TAG, "Unable to load cryptogram native library", e);
        }
    }

    private CryptogramNative() {
    }

    public boolean isLoaded() {
        return loaded;
    }

    public String getVersion() {
        if (!loaded) {
            return "CRYPTOGRAM Android unavailable";
        }
        return nativeGetVersion();
    }

    public boolean checkDoubleRatchet() {
        return loaded && nativeCheckDoubleRatchet();
    }

    public boolean checkMLS() {
        return loaded && nativeCheckMLS();
    }

    public void initializeStorage() {
        if (!loaded || ApplicationLoader.applicationContext == null) {
            return;
        }
        nativeInitializeStorage(ApplicationLoader.applicationContext.getFilesDir().getAbsolutePath());
    }

    private native String nativeGetVersion();
    private native boolean nativeCheckDoubleRatchet();
    private native boolean nativeCheckMLS();
    private native void nativeInitializeStorage(String path);
}
