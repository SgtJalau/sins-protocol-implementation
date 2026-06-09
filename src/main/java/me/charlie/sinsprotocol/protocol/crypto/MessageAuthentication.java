package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import java.security.MessageDigest;

/**
 * Creates and verifies protocol HMAC values.
 *
 * This class is used both for whole-message MACs and handshake authentication proofs.
 */
public final class MessageAuthentication {

    private MessageAuthentication() {
    }

    /**
     * Computes HMAC-SHA256 and encodes it as Base64URL without padding.
     *
     * @param key MAC key.
     * @param data authenticated bytes.
     * @return Base64URL encoded HMAC.
     */
    public static String hmacBase64Url(byte[] key, byte[] data) {
        return ProtocolEncoding.encodeBase64Url(Hkdf.hmac(key, data));
    }

    /**
     * Computes the protocol msg-mac for a message.
     *
     * @param key epoch MAC key for the sender direction.
     * @param message message whose msg-mac field is excluded from the MAC input.
     * @return Base64URL encoded message MAC.
     */
    public static String messageMac(byte[] key, ProtocolMessage message) {
        return hmacBase64Url(key, ProtocolMessageCodec.canonicalBytesWithoutMessageMac(message));
    }

    /**
     * Verifies a protected message MAC.
     *
     * @param key epoch MAC key for the sender direction.
     * @param message received protocol message.
     * @param receivedMac msg-mac value received on the wire.
     */
    public static void verifyMessageMac(byte[] key, ProtocolMessage message, String receivedMac) {
        String expectedMac = messageMac(key, message);
        if (!constantTimeEquals(expectedMac, receivedMac)) {
            throw new ProtocolException("Invalid message MAC");
        }
    }

    /**
     * Verifies a CLIENT_AUTH or SERVER_AUTH finished value.
     *
     * @param key finished key for the proving endpoint.
     * @param transcriptHash transcript hash the proof must bind to.
     * @param receivedAuthenticationValue received auth-value.
     */
    public static void verifyAuthenticationValue(byte[] key, byte[] transcriptHash, String receivedAuthenticationValue) {
        String expectedAuthenticationValue = hmacBase64Url(key, transcriptHash);
        if (!constantTimeEquals(expectedAuthenticationValue, receivedAuthenticationValue)) {
            throw new ProtocolException("Invalid authentication value");
        }
    }

    /**
     * Compares encoded MAC values without data-dependent early exit.
     */
    private static boolean constantTimeEquals(String expected, String actual) {
        byte[] expectedBytes = ProtocolEncoding.utf8(expected);
        byte[] actualBytes = ProtocolEncoding.utf8(actual);
        return MessageDigest.isEqual(expectedBytes, actualBytes);
    }
}
