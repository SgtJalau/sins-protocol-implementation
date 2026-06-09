package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import java.security.MessageDigest;

public final class MessageAuthentication {

    private MessageAuthentication() {
    }

    public static String hmacBase64Url(byte[] key, byte[] data) {
        return ProtocolEncoding.encodeBase64Url(Hkdf.hmac(key, data));
    }

    public static String messageMac(byte[] key, ProtocolMessage message) {
        return hmacBase64Url(key, ProtocolMessageCodec.canonicalBytesWithoutMessageMac(message));
    }

    public static void verifyMessageMac(byte[] key, ProtocolMessage message, String receivedMac) {
        String expectedMac = messageMac(key, message);
        if (!constantTimeEquals(expectedMac, receivedMac)) {
            throw new ProtocolException("Invalid message MAC");
        }
    }

    public static void verifyAuthenticationValue(byte[] key, byte[] transcriptHash, String receivedAuthenticationValue) {
        String expectedAuthenticationValue = hmacBase64Url(key, transcriptHash);
        if (!constantTimeEquals(expectedAuthenticationValue, receivedAuthenticationValue)) {
            throw new ProtocolException("Invalid authentication value");
        }
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        byte[] expectedBytes = ProtocolEncoding.utf8(expected);
        byte[] actualBytes = ProtocolEncoding.utf8(actual);
        return MessageDigest.isEqual(expectedBytes, actualBytes);
    }
}
