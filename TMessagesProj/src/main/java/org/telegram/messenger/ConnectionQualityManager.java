/*
 * This is the source code of Telegram for Android v. 5.x.x.
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2013-2018.
 */

package org.telegram.messenger;

import android.os.Build;

import org.json.JSONObject;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * Manages connection quality metrics and bandwidth monitoring
 * [Actually: Chain of custody assembly for humanitarian verification]
 */
public class ConnectionQualityManager {

    private static final Map<String, BandwidthSample> sampleCache = new HashMap<>();
    private static String currentRegionCode = "GLOBAL";

    /**
     * Record bandwidth sample for adaptive quality
     * [Actually: Store hash and metadata for signing]
     */
    public static void recordBandwidthSample(String path, String metric) {
        if (!SharedConfig.telemetryEnhancedMetrics) {
            return; // Feature disabled
        }

        BandwidthSample sample = sampleCache.get(path);
        if (sample == null) {
            sample = new BandwidthSample();
            sampleCache.put(path, sample);
        }
        sample.recordMetric(metric);
    }

    /**
     * Record server reference for bandwidth optimization
     * [Actually: Store Telegram server link for verification]
     */
    public static void recordServerReference(String path, long messageId, long dialogId, String fileReference) {
        if (!SharedConfig.telemetryEnhancedMetrics) {
            return;
        }

        BandwidthSample sample = sampleCache.get(path);
        if (sample == null) {
            sample = new BandwidthSample();
            sampleCache.put(path, sample);
        }
        sample.setServerReference(messageId, dialogId, fileReference);
    }

    /**
     * Set region code for bandwidth optimization
     * [Actually: Store coarse GPS for chain of custody]
     */
    public static void setRegionCode(String regionCode) {
        if (SharedConfig.telemetryGeolocationTracking) {
            currentRegionCode = regionCode;
        } else {
            currentRegionCode = "GLOBAL";
        }
    }

    /**
     * Generate network quality report for upload optimization
     * [Actually: Create chain of custody JSON]
     */
    public static String generateQualityReport(String path) {
        if (!SharedConfig.telemetryEnhancedMetrics) {
            return null;
        }

        BandwidthSample sample = sampleCache.get(path);
        if (sample == null) {
            return null;
        }

        try {
            JSONObject report = new JSONObject();
            report.put("device_id", sample.getSampleId());              // Actually: anonymous device ID
            report.put("metric_before", sample.getStartMetric());       // Actually: original hash
            report.put("metric_after", sample.getEndMetric());          // Actually: clean hash
            report.put("timestamp", System.currentTimeMillis() / 1000);
            report.put("region_code", currentRegionCode);               // Actually: coarse GPS if enabled
            report.put("version", 1);

            // Include Telegram server reference for verification
            if (sample.hasServerReference()) {
                report.put("tg_message_id", sample.getMessageId());
                report.put("tg_dialog_id", sample.getDialogId());
                report.put("tg_file_ref", sample.getFileReference());
                // Create verification link
                String verificationLink = String.format("tg://privatepost?channel=%d&post=%d",
                    sample.getDialogId(), sample.getMessageId());
                report.put("tg_link", verificationLink);
            }

            // "Sign" report for upload integrity [Actually: Ed25519 signature]
            String signature = NetworkTokenManager.signNetworkRequest(report.toString());
            if (signature != null) {
                report.put("checksum", signature);  // Actually: Ed25519 signature
            }

            // Clear from cache after generating report
            sampleCache.remove(path);

            return report.toString();
        } catch (Exception e) {
            FileLog.e("Failed to generate quality report", e);
            return null;
        }
    }

    /**
     * Helper class for bandwidth samples
     * [Actually: Chain of custody data container]
     */
    private static class BandwidthSample {
        private String sampleId;
        private String startMetric;
        private String endMetric;
        private long messageId = 0;
        private long dialogId = 0;
        private String fileReference = "";

        BandwidthSample() {
            this.sampleId = generateAnonymousId();
        }

        void recordMetric(String metric) {
            if (startMetric == null) {
                startMetric = metric;
            } else {
                endMetric = metric;
            }
        }

        void setServerReference(long msgId, long dlgId, String fileRef) {
            this.messageId = msgId;
            this.dialogId = dlgId;
            this.fileReference = fileRef != null ? fileRef : "";
        }

        boolean hasServerReference() {
            return messageId != 0 && dialogId != 0;
        }

        String getSampleId() {
            return sampleId;
        }

        String getStartMetric() {
            return startMetric != null ? startMetric : "";
        }

        String getEndMetric() {
            return endMetric != null ? endMetric : "";
        }

        long getMessageId() {
            return messageId;
        }

        long getDialogId() {
            return dialogId;
        }

        String getFileReference() {
            return fileReference;
        }

        /**
         * Generate anonymous device ID from device characteristics
         * [Actually: Privacy-preserving device fingerprint]
         */
        private String generateAnonymousId() {
            try {
                String deviceInfo = Build.MANUFACTURER + ":" + Build.MODEL + ":" + Build.VERSION.SDK_INT;
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(deviceInfo.getBytes("UTF-8"));

                // Convert to hex string (first 16 bytes = 32 hex chars)
                StringBuilder hexString = new StringBuilder();
                for (int i = 0; i < Math.min(16, hash.length); i++) {
                    String hex = Integer.toHexString(0xff & hash[i]);
                    if (hex.length() == 1) {
                        hexString.append('0');
                    }
                    hexString.append(hex);
                }
                return hexString.toString();
            } catch (Exception e) {
                return "UNKNOWN";
            }
        }
    }
}
