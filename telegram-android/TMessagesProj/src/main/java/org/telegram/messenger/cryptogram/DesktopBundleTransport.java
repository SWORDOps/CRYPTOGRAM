/*
 * CRYPTOGRAM Desktop key-bundle transport — Java port.
 *
 * Faithful port of Telegram/SourceFiles/data/data_signal_transport.cpp
 * (zwEncode/zwDecode/encodeKeyBundle/decodeKeyBundle/extractAndStripBundles/
 * buildOutgoingEntity) so desktop and Android exchange key bundles over the
 * same wire format: an invisible zero-width payload inside the message text,
 * covered by a messageEntityUnknown(offset=0, length) entity.
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

package org.telegram.messenger.cryptogram;

import org.telegram.tgnet.TLRPC;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Zero-width transport for Double Ratchet key bundles, byte-compatible with
 * CRYPTOGRAM Desktop (Data::SignalProtocolTransport).
 *
 * Binary bundle layout (all multi-byte integers LITTLE-ENDIAN):
 *   [u8]  version = 0x01
 *   [u8]  bitmap: 0x01 = oneTimePreKey present, 0x02 = quantum KEM extension
 *         (u16le length + SPKI DER bytes — emitted when the native bundle
 *         carries a static ML-KEM public key, desktop PQ parity),
 *         0x04 = X25519 identity extension (u16le length + 32 bytes)
 *   [u64] registrationId
 *   [32]  identityKey
 *   [32]  signedPreKey
 *   [64]  signature
 *   [32]  oneTimePreKey (only if bitmap & 0x01)
 *   extensions in bitmap order, each: [u16le length][bytes]
 *
 * Zero-width base-4 alphabet (most-significant pair first, 4 chars per byte):
 *   U+200B = 00, U+200C = 01, U+200D = 10, U+FEFF = 11
 */
public final class DesktopBundleTransport {

    public static final int TRANSPORT_VERSION = 0x01;

    public static final int FLAG_ONE_TIME_PRE_KEY = 0x01;
    public static final int FLAG_QUANTUM_KEM = 0x02;
    public static final int FLAG_X25519_IDENTITY = 0x04;

    // version(1) + bitmap(1) + regId(8) + identityKey(32) + signedPreKey(32)
    // + signature(64) = 138 bytes without oneTimePreKey (kMinPayloadBytes).
    private static final int MIN_PAYLOAD_BYTES = 138;
    private static final int MAX_QUANTUM_KEM_LEN = 4096;

    public static final char ZW_SPACE = '\u200B';
    public static final char ZW_NON_JOINER = '\u200C';
    public static final char ZW_JOINER = '\u200D';
    public static final char ZW_NO_BREAK_SPACE = '\uFEFF';

    private static final char[] ZW_ALPHABET = {
        ZW_SPACE, ZW_NON_JOINER, ZW_JOINER, ZW_NO_BREAK_SPACE
    };

    private DesktopBundleTransport() {
    }

    /**
     * Decoded desktop key bundle. Extension payloads are null when absent.
     */
    public static final class DecodedBundle {
        public long registrationId;
        public byte[] identityKey;
        public byte[] signedPreKey;
        public byte[] signature;
        public byte[] oneTimePreKey;
        public byte[] quantumKemPublicKey;
        public byte[] x25519IdentityKey;
    }

    // ------------------------------------------------------------------
    // Zero-width encoding
    // ------------------------------------------------------------------

    /**
     * Encode raw bytes as invisible zero-width text (base-4, 4 chars per byte,
     * most-significant pair first) — port of desktop zwEncode.
     */
    public static String zwEncode(byte[] data) {
        if (data == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(data.length * 4);
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out.append(ZW_ALPHABET[(v >> 6) & 0x3]);
            out.append(ZW_ALPHABET[(v >> 4) & 0x3]);
            out.append(ZW_ALPHABET[(v >> 2) & 0x3]);
            out.append(ZW_ALPHABET[v & 0x3]);
        }
        return out.toString();
    }

    /**
     * Decode invisible zero-width text back to raw bytes — port of desktop
     * zwDecode. Returns an empty array on invalid input (odd length or any
     * unexpected code point).
     */
    public static byte[] zwDecode(String text) {
        if (text == null || text.length() % 4 != 0) {
            return new byte[0];
        }
        byte[] out = new byte[text.length() / 4];
        for (int i = 0; i < text.length(); i += 4) {
            int value = 0;
            for (int j = 0; j < 4; j++) {
                int bits = zwBits(text.charAt(i + j));
                if (bits < 0) {
                    return new byte[0];
                }
                value = (value << 2) | bits;
            }
            out[i / 4] = (byte) value;
        }
        return out;
    }

    /**
     * @return the 2-bit value for a zero-width alphabet char, or -1 otherwise.
     */
    public static int zwBits(char ch) {
        for (int k = 0; k < 4; k++) {
            if (ch == ZW_ALPHABET[k]) {
                return k;
            }
        }
        return -1;
    }

    // ------------------------------------------------------------------
    // Serialisation (desktop v1 layout, little-endian)
    // ------------------------------------------------------------------

    /**
     * Serialise a key bundle into the desktop v1 transport layout (no KEM
     * extension — see the full overload).
     *
     * @return the encoded bundle, or an empty array on invalid key sizes.
     */
    public static byte[] encodeKeyBundle(byte[] identityKey, byte[] signedPreKey, byte[] signature,
                                         byte[] oneTimePreKey, long registrationId, byte[] x25519IdentityKey) {
        return encodeKeyBundle(identityKey, signedPreKey, signature,
            oneTimePreKey, registrationId, x25519IdentityKey, null);
    }

    /**
     * Serialise a key bundle into the desktop v1 transport layout, including
     * the post-quantum extension (bitmap 0x02: u16le length + SPKI DER) when
     * {@param quantumKemPublicKey} is non-empty — desktop PQ parity; the
     * native layer carries the static ML-KEM public key in its bundle.
     *
     * @return the encoded bundle, or an empty array on invalid key sizes.
     */
    public static byte[] encodeKeyBundle(byte[] identityKey, byte[] signedPreKey, byte[] signature,
                                         byte[] oneTimePreKey, long registrationId, byte[] x25519IdentityKey,
                                         byte[] quantumKemPublicKey) {
        if (identityKey == null || identityKey.length != 32
                || signedPreKey == null || signedPreKey.length != 32
                || signature == null || signature.length != 64) {
            return new byte[0];
        }
        final boolean hasOtp = oneTimePreKey != null && oneTimePreKey.length == 32;
        final boolean hasXid = x25519IdentityKey != null && x25519IdentityKey.length == 32;
        final boolean hasKem = quantumKemPublicKey != null && quantumKemPublicKey.length > 0
            && quantumKemPublicKey.length <= MAX_QUANTUM_KEM_LEN;
        final int bitmap = (hasOtp ? FLAG_ONE_TIME_PRE_KEY : 0)
            | (hasKem ? FLAG_QUANTUM_KEM : 0)
            | (hasXid ? FLAG_X25519_IDENTITY : 0);

        final int size = MIN_PAYLOAD_BYTES + (hasOtp ? 32 : 0)
            + (hasKem ? 2 + quantumKemPublicKey.length : 0)
            + (hasXid ? 2 + 32 : 0);
        final ByteBuffer out = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        out.put((byte) TRANSPORT_VERSION);
        out.put((byte) bitmap);
        out.putLong(registrationId);
        out.put(identityKey);
        out.put(signedPreKey);
        out.put(signature);
        if (hasOtp) {
            out.put(oneTimePreKey);
        }
        // Extensions in bitmap order: 0x02 before 0x04.
        if (hasKem) {
            out.putShort((short) quantumKemPublicKey.length);
            out.put(quantumKemPublicKey);
        }
        if (hasXid) {
            out.putShort((short) 32);
            out.put(x25519IdentityKey);
        }
        return out.array();
    }

    /**
     * Parse a desktop v1 transport bundle — port of desktop decodeKeyBundle.
     * Unknown trailing bytes (e.g. from newer extensions) are tolerated.
     *
     * @return the decoded bundle, or null when the payload is not a valid v1 bundle.
     */
    public static DecodedBundle decodeKeyBundle(byte[] raw) {
        if (raw == null || raw.length < MIN_PAYLOAD_BYTES) {
            return null;
        }
        final ByteBuffer in = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);

        final int version = in.get() & 0xFF;
        if (version != TRANSPORT_VERSION) {
            return null;
        }
        final int bitmap = in.get() & 0xFF;

        final DecodedBundle bundle = new DecodedBundle();
        bundle.registrationId = in.getLong();
        bundle.identityKey = readBytes(in, 32);
        bundle.signedPreKey = readBytes(in, 32);
        bundle.signature = readBytes(in, 64);
        if (bundle.identityKey == null || bundle.signedPreKey == null || bundle.signature == null) {
            return null;
        }
        if ((bitmap & FLAG_ONE_TIME_PRE_KEY) != 0) {
            bundle.oneTimePreKey = readBytes(in, 32);
            if (bundle.oneTimePreKey == null) {
                return null;
            }
        }

        // Optional post-quantum extension (bitmap 0x02): u16le length + SPKI
        // DER. Emitted by desktop and (PQ parity) by Android when the native
        // bundle carries a static ML-KEM public key. An invalid length is
        // skipped without consuming (matching the desktop parser), leaving the
        // bytes to be ignored as trailing garbage.
        if ((bitmap & FLAG_QUANTUM_KEM) != 0 && in.remaining() >= 2) {
            final int pqLen = in.getShort() & 0xFFFF;
            if (pqLen > 0 && pqLen <= MAX_QUANTUM_KEM_LEN) {
                bundle.quantumKemPublicKey = readBytes(in, pqLen);
                if (bundle.quantumKemPublicKey == null) {
                    return null;
                }
            }
        }

        // Optional X3DH fix extension (bitmap 0x04): u16le length (=32) + key.
        if ((bitmap & FLAG_X25519_IDENTITY) != 0 && in.remaining() >= 2) {
            final int xidLen = in.getShort() & 0xFFFF;
            if (xidLen == 32) {
                bundle.x25519IdentityKey = readBytes(in, 32);
                if (bundle.x25519IdentityKey == null) {
                    return null;
                }
            }
        }

        // Trailing unknown bytes are intentionally ignored.
        return bundle;
    }

    private static byte[] readBytes(ByteBuffer in, int size) {
        if (in.remaining() < size) {
            return null;
        }
        byte[] out = new byte[size];
        in.get(out);
        return out;
    }

    // ------------------------------------------------------------------
    // Entity helpers
    // ------------------------------------------------------------------

    /**
     * Build the outgoing messageEntityUnknown(0, len) entity covering the
     * zero-width encoding of the raw bundle payload (port of desktop
     * buildOutgoingEntity; the caller must prepend zwEncode(rawBundlePayload)
     * to the message text, exactly like the desktop caller does).
     */
    public static TLRPC.TL_messageEntityUnknown buildOutgoingEntity(byte[] rawBundlePayload) {
        return buildOutgoingEntity(zwEncode(rawBundlePayload));
    }

    /**
     * Build the outgoing entity for an already zero-width-encoded payload.
     */
    public static TLRPC.TL_messageEntityUnknown buildOutgoingEntity(String zwPayload) {
        TLRPC.TL_messageEntityUnknown entity = new TLRPC.TL_messageEntityUnknown();
        entity.offset = 0;
        entity.length = zwPayload.length();
        return entity;
    }

    /**
     * Find messageEntityUnknown entities whose covered text is entirely
     * zero-width alphabet characters, decode them as desktop key bundles and
     * REMOVE the consumed entities from the list (desktop
     * extractAndStripBundles semantics). Out-of-range offsets are skipped.
     *
     * @return the decoded raw bundle payloads.
     */
    public static List<byte[]> extractBundles(ArrayList<TLRPC.MessageEntity> entities, String messageText) {
        return extractBundles(entities, messageText, null);
    }

    /**
     * Same as {@link #extractBundles(ArrayList, String)}, additionally reports
     * the consumed [offset, length) text ranges into {@param consumedRangesOut}
     * when non-null (used to strip the invisible payload from the shown text).
     */
    public static List<byte[]> extractBundles(ArrayList<TLRPC.MessageEntity> entities, String messageText,
                                              List<int[]> consumedRangesOut) {
        List<byte[]> result = new ArrayList<>();
        if (entities == null || entities.isEmpty() || messageText == null || messageText.isEmpty()) {
            return result;
        }
        final Iterator<TLRPC.MessageEntity> it = entities.iterator();
        while (it.hasNext()) {
            final TLRPC.MessageEntity entity = it.next();
            if (!(entity instanceof TLRPC.TL_messageEntityUnknown)) {
                continue;
            }
            final int offset = entity.offset;
            final int length = entity.length;
            // Validate range (overflow-safe).
            if (offset < 0 || length <= 0 || offset >= messageText.length()
                    || length > messageText.length() - offset) {
                continue;
            }
            // The payload is invisible zero-width chars in the message text;
            // confirm all covered chars are from our alphabet.
            boolean allZeroWidth = true;
            for (int i = offset; i < offset + length; i++) {
                if (zwBits(messageText.charAt(i)) < 0) {
                    allZeroWidth = false;
                    break;
                }
            }
            if (!allZeroWidth) {
                continue;
            }
            final byte[] raw = zwDecode(messageText.substring(offset, offset + length));
            if (raw.length == 0) {
                continue;
            }
            if (decodeKeyBundle(raw) == null) {
                continue;
            }
            result.add(raw);
            if (consumedRangesOut != null) {
                consumedRangesOut.add(new int[]{offset, length});
            }
            it.remove();
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Native bridge adapters
    //
    // ASSUMPTION: after the concurrent CryptogramWrapper.cpp refactor,
    // DoubleRatchet.generateKeyBundle() emits the desktop v1 transport layout
    // directly and initializeWithRemoteBundle() consumes it. Until that lands,
    // the current native layer uses a legacy wrapper:
    //   u32le deviceIdLength | deviceId bytes | u64le registrationId |
    //   u32le-prefixed identityKey, signedPreKey, oneTimePreKey, signature
    // The helpers below detect the format and convert between the two so the
    // transport keeps working in either native state.
    // TODO(cryptogram): remove the legacy adapters once CryptogramWrapper.cpp
    // speaks the desktop transport natively.
    // ------------------------------------------------------------------

    /**
     * @return true when the bytes plausibly are a desktop v1 transport bundle.
     */
    public static boolean isDesktopTransport(byte[] raw) {
        return raw != null && raw.length >= MIN_PAYLOAD_BYTES
            && (raw[0] & 0xFF) == TRANSPORT_VERSION && (raw[1] & 0xFF) <= 0x07;
    }

    // ------------------------------------------------------------------
    // Desktop MESSAGE-ENVELOPE framing (data_signal_protocol.cpp
    // wrapEncryptedText/unwrapEncryptedText). Deliberately a SECOND
    // alphabet: the key-bundle transport above uses U+FEFF as the 4th
    // zero-width char, while the message envelope uses U+2060 there and a
    // different marker. Byte-for-byte ports of both.
    // ------------------------------------------------------------------

    public static final char[] DESKTOP_MESSAGE_ALPHABET =
        {'\u200B', '\u200C', '\u200D', '\u2060'};
    public static final String DESKTOP_MESSAGE_MARKER =
        "\uFEFF\u200B\u200C\uFEFF";

    /** @return true when the text is a desktop-framed message envelope. */
    public static boolean isDesktopEnvelope(String text) {
        if (text == null || !text.startsWith(DESKTOP_MESSAGE_MARKER)) {
            return false;
        }
        final int payloadStart = DESKTOP_MESSAGE_MARKER.length();
        if ((text.length() - payloadStart) % 4 != 0) {
            return false;
        }
        for (int i = payloadStart; i < text.length(); ++i) {
            final int cp = text.charAt(i);
            if (cp != 0x200B && cp != 0x200C && cp != 0x200D && cp != 0x2060) {
                return false;
            }
        }
        return text.length() > payloadStart;
    }

    /** Zero-width-encode raw envelope bytes with the desktop message alphabet. */
    public static String encodeDesktopMessageEnvelope(byte[] envelope) {
        if (envelope == null || envelope.length == 0) {
            return null;
        }
        final StringBuilder out = new StringBuilder(
            DESKTOP_MESSAGE_MARKER.length() + envelope.length * 4);
        out.append(DESKTOP_MESSAGE_MARKER);
        for (final byte b : envelope) {
            final int v = b & 0xFF;
            out.append(DESKTOP_MESSAGE_ALPHABET[(v >> 6) & 3]);
            out.append(DESKTOP_MESSAGE_ALPHABET[(v >> 4) & 3]);
            out.append(DESKTOP_MESSAGE_ALPHABET[(v >> 2) & 3]);
            out.append(DESKTOP_MESSAGE_ALPHABET[v & 3]);
        }
        return out.toString();
    }

    /**
     * Decode a desktop message-envelope text. Returns null when the text is
     * not a desktop envelope (no marker or non-alphabet characters), matching
     * the desktop's unwrapEncryptedText bail-out semantics.
     */
    public static byte[] decodeDesktopMessageEnvelope(String text) {
        if (text == null || !isDesktopEnvelope(text)) {
            return null;
        }
        final int payloadStart = DESKTOP_MESSAGE_MARKER.length();
        if ((text.length() - payloadStart) % 4 != 0) {
            return null;
        }
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = payloadStart; i + 3 < text.length(); i += 4) {
            int bits = 0;
            for (int j = 0; j < 4; ++j) {
                final int cp = text.charAt(i + j);
                final int val;
                if (cp == 0x200B) val = 0;
                else if (cp == 0x200C) val = 1;
                else if (cp == 0x200D) val = 2;
                else if (cp == 0x2060) val = 3;
                else return null;
                bits = (bits << 2) | val;
            }
            out.write(bits);
        }
        return out.size() > 0 ? out.toByteArray() : null;
    }

    /**
     * Map whatever the native layer currently produces to the desktop v1
     * transport layout. Desktop-format bytes pass through untouched; legacy
     * native bundles are re-encoded (deviceId identifier has no desktop
     * equivalent and is dropped). Unknown bytes pass through unchanged so the
     * remote side rejects them, never us.
     */
    public static byte[] fromNativeBundle(byte[] nativeBundle) {
        if (nativeBundle == null || nativeBundle.length == 0 || isDesktopTransport(nativeBundle)) {
            return nativeBundle;
        }
        final DecodedBundle legacy = parseLegacyNativeBundle(nativeBundle);
        if (legacy == null) {
            return nativeBundle;
        }
        final byte[] transport = encodeKeyBundle(legacy.identityKey, legacy.signedPreKey, legacy.signature,
            legacy.oneTimePreKey, legacy.registrationId, legacy.x25519IdentityKey,
            legacy.quantumKemPublicKey);
        return transport.length > 0 ? transport : nativeBundle;
    }

    /**
     * Re-wrap a desktop v1 transport bundle in the legacy native layout for
     * native layers that still parse it.
     * TODO(cryptogram): remove with the other legacy adapters.
     */
    public static byte[] toLegacyNativeBundle(byte[] transportBundle) {
        final DecodedBundle bundle = decodeKeyBundle(transportBundle);
        if (bundle == null) {
            return null;
        }
        int size = 4 + 8;
        size += 4 + 32 + 4 + 32 + 4 + 64; // identityKey, signedPreKey, signature
        if (bundle.oneTimePreKey != null) {
            size += 4 + bundle.oneTimePreKey.length;
        }
        final ByteBuffer out = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        out.putInt(0); // legacy deviceId identifier (no desktop equivalent)
        out.putLong(bundle.registrationId);
        putVector(out, bundle.identityKey);
        putVector(out, bundle.signedPreKey);
        putVector(out, bundle.oneTimePreKey != null ? bundle.oneTimePreKey : new byte[0]);
        putVector(out, bundle.signature);
        return out.array();
    }

    /**
     * Parse the legacy native key-bundle wrapper (little-endian, see
     * CryptogramWrapper.cpp serializeKeyBundle).
     */
    private static DecodedBundle parseLegacyNativeBundle(byte[] legacy) {
        final ByteBuffer in = ByteBuffer.wrap(legacy).order(ByteOrder.LITTLE_ENDIAN);
        if (in.remaining() < 4) {
            return null;
        }
        final int idLen = in.getInt();
        if (idLen < 0 || idLen > 512 || in.remaining() < idLen + 8) {
            return null;
        }
        in.position(in.position() + idLen);
        final DecodedBundle bundle = new DecodedBundle();
        bundle.registrationId = in.getLong();
        bundle.identityKey = readVector(in);
        bundle.signedPreKey = readVector(in);
        bundle.oneTimePreKey = readVector(in);
        bundle.signature = readVector(in);
        if (bundle.identityKey == null || bundle.signedPreKey == null || bundle.signature == null) {
            return null;
        }
        if (bundle.oneTimePreKey != null && bundle.oneTimePreKey.length != 32) {
            bundle.oneTimePreKey = null;
        }
        return bundle;
    }

    private static byte[] readVector(ByteBuffer in) {
        if (in.remaining() < 4) {
            return null;
        }
        final int len = in.getInt();
        if (len < 0 || len > in.remaining()) {
            return null;
        }
        return readBytes(in, len);
    }

    private static void putVector(ByteBuffer out, byte[] value) {
        out.putInt(value.length);
        out.put(value);
    }
}
