package me.charlie.sinsprotocol.protocol.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class ProtocolEncoding {

    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private ProtocolEncoding() {
    }

    public static String randomBase64Url(int byteCount) {
        byte[] randomBytes = new byte[byteCount];
        SECURE_RANDOM.nextBytes(randomBytes);
        return encodeBase64Url(randomBytes);
    }

    public static String encodeBase64Url(byte[] bytes) {
        return BASE64_URL_ENCODER.encodeToString(bytes);
    }

    public static byte[] decodeBase64Url(String encoded) {
        return BASE64_URL_DECODER.decode(encoded);
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    //AES-GCM uses one unique 96-bit nonce per encrypted DATA_RESPONSE.
    public static byte[] dataResponseNonce(int epoch, long sequenceNumber) {
        return ByteBuffer.allocate(12)
                .putInt(epoch)
                .putLong(sequenceNumber)
                .array();
    }
}
