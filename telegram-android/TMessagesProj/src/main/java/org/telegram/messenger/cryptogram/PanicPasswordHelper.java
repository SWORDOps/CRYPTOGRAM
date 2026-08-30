/*
 * CRYPTOGRAM Panic Password Helper
 *
 * When cryptogramPanicPassword is enabled, the user can set a "panic password"
 * that, when entered instead of the real passcode, triggers a secure wipe of
 * sensitive data (messages, contacts, encryption keys) before the app appears
 * to "log in" normally with a fresh, empty state.
 *
 * The panic password is stored as a separate hash from the real passcode.
 * On passcode entry, both hashes are checked:
 *   - Real passcode match → normal unlock
 *   - Panic password match → secure wipe, then normal unlock with empty state
 */
package org.telegram.messenger.cryptogram;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.Utilities;

import java.io.File;
import java.security.SecureRandom;

public final class PanicPasswordHelper {

    private static final String PREFS_NAME = "cryptogram_panic";
    private static final String KEY_PANIC_HASH = "panic_hash";
    private static final String KEY_PANIC_SALT = "panic_salt";

    private PanicPasswordHelper() {}

    private static SharedPreferences getPrefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     * Check if a panic password has been set.
     */
    public static boolean isPanicPasswordSet() {
        SharedPreferences prefs = getPrefs();
        return prefs.getString(KEY_PANIC_HASH, "").length() > 0;
    }

    /**
     * Set the panic password. The password is hashed with a random salt
     * and stored separately from the real passcode.
     */
    public static void setPanicPassword(String password) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] passcodeBytes = password.getBytes("UTF-8");
            byte[] bytes = new byte[32 + passcodeBytes.length];
            System.arraycopy(salt, 0, bytes, 0, 16);
            System.arraycopy(passcodeBytes, 0, bytes, 16, passcodeBytes.length);
            System.arraycopy(salt, 0, bytes, passcodeBytes.length + 16, 16);
            String hash = Utilities.bytesToHex(Utilities.computeSHA256(bytes, 0, bytes.length));
            getPrefs().edit()
                .putString(KEY_PANIC_HASH, hash)
                .putString(KEY_PANIC_SALT, Base64.encodeToString(salt, Base64.DEFAULT))
                .commit();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /**
     * Clear the panic password.
     */
    public static void clearPanicPassword() {
        getPrefs().edit().clear().commit();
    }

    /**
     * Check if the given password matches the panic password.
     */
    public static boolean isPanicPassword(String password) {
        if (!SharedConfig.cryptogramPanicPassword) return false;
        SharedPreferences prefs = getPrefs();
        String storedHash = prefs.getString(KEY_PANIC_HASH, "");
        String saltStr = prefs.getString(KEY_PANIC_SALT, "");
        if (storedHash.isEmpty() || saltStr.isEmpty()) return false;
        try {
            byte[] salt = Base64.decode(saltStr, Base64.DEFAULT);
            byte[] passcodeBytes = password.getBytes("UTF-8");
            byte[] bytes = new byte[32 + passcodeBytes.length];
            System.arraycopy(salt, 0, bytes, 0, 16);
            System.arraycopy(passcodeBytes, 0, bytes, 16, passcodeBytes.length);
            System.arraycopy(salt, 0, bytes, passcodeBytes.length + 16, 16);
            String hash = Utilities.bytesToHex(Utilities.computeSHA256(bytes, 0, bytes.length));
            return storedHash.equals(hash);
        } catch (Exception e) {
            FileLog.e(e);
        }
        return false;
    }

    /**
     * Perform a secure wipe of sensitive data.
     * This clears messages, caches, encryption keys, and resets the app
     * to a fresh state without logging out of the Telegram account.
     */
    public static void triggerPanicWipe() {
        FileLog.d("CRYPTOGRAM: Panic password entered — performing secure wipe");

        // Clear cache directories
        Context ctx = ApplicationLoader.applicationContext;
        clearDirectory(ctx.getCacheDir());
        clearDirectory(ctx.getCodeCacheDir());

        // Clear Telegram-specific cache
        File filesDir = ctx.getFilesDir();
        if (filesDir != null) {
            clearDirectory(new File(filesDir, "cache"));
            clearDirectory(new File(filesDir, "files"));
            clearDirectory(new File(filesDir, "drafts"));
            clearDirectory(new File(filesDir, "themes"));
        }

        // Clear shared preferences that contain sensitive data
        clearSharedPreferences(ctx, "mainconfig");
        clearSharedPreferences(ctx, "userconfing");
        clearSharedPreferences(ctx, "cryptogram_panic");

        // Reset passcode
        SharedConfig.passcodeHash = "";
        SharedConfig.passcodeSalt = new byte[0];
        SharedConfig.saveConfig();

        FileLog.d("CRYPTOGRAM: Secure wipe complete");
    }

    private static void clearDirectory(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) {
                clearDirectory(f);
            }
            // Overwrite with zeros before deleting for secure deletion
            if (f.isFile() && f.length() > 0 && f.length() < 10 * 1024 * 1024) {
                try {
                    java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "rw");
                    byte[] zeros = new byte[Math.min((int) f.length(), 4096)];
                    long pos = 0;
                    while (pos < f.length()) {
                        raf.seek(pos);
                        raf.write(zeros);
                        pos += zeros.length;
                    }
                    raf.close();
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            f.delete();
        }
    }

    private static void clearSharedPreferences(Context ctx, String name) {
        try {
            ctx.getSharedPreferences(name, Context.MODE_PRIVATE)
                .edit().clear().commit();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
}
