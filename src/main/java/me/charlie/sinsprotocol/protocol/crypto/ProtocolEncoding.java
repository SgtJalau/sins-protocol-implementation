package me.charlie.sinsprotocol.protocol.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Shared binary/string encoding utilities for protocol values.
 */
public final class ProtocolEncoding {

    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private ProtocolEncoding() {
    }

    /**
     * Generates random bytes and encodes them as Base64URL without padding.
     * @param byteCount number of random bytes before encoding.
     * @return Base64URL encoded random value.
     */
    public static String randomBase64Url(int byteCount) {
        byte[] randomBytes = new byte[byteCount];
        SECURE_RANDOM.nextBytes(randomBytes);
        return encodeBase64Url(randomBytes);
    }

    /**
     * @param bytes raw bytes to encode.
     * @return Base64URL string without padding.
     */
    public static String encodeBase64Url(byte[] bytes) {
        return BASE64_URL_ENCODER.encodeToString(bytes);
    }

    /**
     * @param encoded Base64URL string without padding.
     * @return decoded raw bytes.
     */
    public static byte[] decodeBase64Url(String encoded) {
        return BASE64_URL_DECODER.decode(encoded);
    }

    /**
     * @param value text value.
     * @return UTF-8 encoded bytes.
     */
    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Builds the AES-GCM DATA_RESPONSE nonce.
     * @param epoch current response epoch.
     * @param sequenceNumber server-side DATA_RESPONSE sequence number.
     * @return 12-byte nonce: 32-bit epoch followed by 64-bit sequence number.
     */
    public static byte[] dataResponseNonce(int epoch, long sequenceNumber) {
        return ByteBuffer.allocate(12)
                .putInt(epoch)
                .putLong(sequenceNumber)
                .array();
    }
}
