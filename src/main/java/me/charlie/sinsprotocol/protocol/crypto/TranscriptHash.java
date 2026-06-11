package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.ProtocolSpec;
import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Builds transcript hashes from canonical handshake messages.
 *
 * The transcript binds authentication to the exact HELLO/HELLO_ACK/CLIENT_AUTH values that were exchanged.
 */
public final class TranscriptHash {

    private TranscriptHash() {
    }

    /**
     * Hashes HELLO and HELLO_ACK for initial key derivation and CLIENT_AUTH.
     * @param helloMessage client HELLO.
     * @param helloAckMessage server HELLO_ACK.
     * @return SHA-256 transcript hash.
     */
    public static byte[] initial(HelloMessage helloMessage, HelloAckMessage helloAckMessage) {
        return sha256(
                ProtocolMessageCodec.canonicalBytes(helloMessage),
                ProtocolMessageCodec.canonicalBytes(helloAckMessage)
        );
    }

    /**
     * Hashes HELLO, HELLO_ACK and CLIENT_AUTH without msg-mac for SERVER_AUTH.
     * @param helloMessage client HELLO.
     * @param helloAckMessage server HELLO_ACK.
     * @param clientAuthMessage client auth message.
     * @return SHA-256 transcript hash including CLIENT_AUTH without msg-mac.
     */
    public static byte[] withClientAuth(HelloMessage helloMessage, HelloAckMessage helloAckMessage, ClientAuthMessage clientAuthMessage) {
        return sha256(
                ProtocolMessageCodec.canonicalBytes(helloMessage),
                ProtocolMessageCodec.canonicalBytes(helloAckMessage),
                ProtocolMessageCodec.canonicalBytesWithoutMessageMac(clientAuthMessage)
        );
    }

    /**
     * Hashes the supplied byte parts in order.
     */
    private static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(ProtocolSpec.HASH_ALGORITHM);
            ByteArrayOutputStream transcript = new ByteArrayOutputStream();
            for (byte[] part : parts) {
                transcript.writeBytes(part);
            }

            return messageDigest.digest(transcript.toByteArray());
        } catch (NoSuchAlgorithmException exception) {
            throw new ProtocolException(ProtocolSpec.HASH_ALGORITHM + " is not available", exception);
        }
    }
}
