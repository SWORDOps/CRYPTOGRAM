/*
 * CRYPTOGRAM Anti-Forensics Helper
 * Reduces forensic traces by clearing clipboard, purging caches,
 * and preventing sensitive data from persisting on disk.
 */
package org.telegram.messenger.cryptogram;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.text.TextUtils;

import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.SecureRandom;

public final class AntiForensicsHelper {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void clearClipboard() {
        try {
            Context ctx = ApplicationLoader.applicationContext;
            if (ctx == null) return;
            ClipboardManager clipboard = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                ClipData empty = ClipData.newPlainText("", "");
                clipboard.setPrimaryClip(empty);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /**
     * Securely overwrite a file's contents before deletion to prevent recovery.
     */
    public static void secureDelete(File file) {
        if (file == null || !file.exists()) return;
        try {
            long length = file.length();
            if (length > 0) {
                RandomAccessFile raf = new RandomAccessFile(file, "rws");
                byte[] zeros = new byte[4096];
                for (long pos = 0; pos < length; pos += zeros.length) {
                    int toWrite = (int) Math.min(zeros.length, length - pos);
                    raf.write(zeros, 0, toWrite);
                }
                raf.getFD().sync();
                raf.close();
            }
        } catch (Exception e) {
            // Best effort — fall through to delete
        } finally {
            file.delete();
        }
    }

    /**
     * Purge cache directory contents with secure deletion.
     */
    public static void purgeCache(File cacheDir) {
        if (cacheDir == null || !cacheDir.isDirectory()) return;
        File[] files = cacheDir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) {
                purgeCache(f);
            } else {
                secureDelete(f);
            }
        }
    }

    /**
     * Called when the app is backgrounded — clears clipboard if anti-forensics is enabled.
     */
    public static void onAppBackgrounded() {
        clearClipboard();
    }

    /**
     * Called when the app is destroyed — purges temporary caches.
     */
    public static void onAppDestroyed() {
        try {
            Context ctx = ApplicationLoader.applicationContext;
            if (ctx == null) return;
            File cacheDir = ctx.getCacheDir();
            if (cacheDir != null) {
                purgeCache(cacheDir);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
}
