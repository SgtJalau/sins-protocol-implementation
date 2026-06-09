package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class TranscriptHash {

    private TranscriptHash() {
    }

    public static byte[] initial(HelloMessage helloMessage, HelloAckMessage helloAckMessage) {
        return sha256(
                ProtocolMessageCodec.canonicalBytes(helloMessage),
                ProtocolMessageCodec.canonicalBytes(helloAckMessage)
        );
    }

    public static byte[] withClientAuth(
            HelloMessage helloMessage,
            HelloAckMessage helloAckMessage,
            ClientAuthMessage clientAuthMessage
    ) {
        return sha256(
                ProtocolMessageCodec.canonicalBytes(helloMessage),
                ProtocolMessageCodec.canonicalBytes(helloAckMessage),
                ProtocolMessageCodec.canonicalBytesWithoutMessageMac(clientAuthMessage)
        );
    }

    private static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream transcript = new ByteArrayOutputStream();
            for (byte[] part : parts) {
                transcript.writeBytes(part);
            }
            return messageDigest.digest(transcript.toByteArray());
        } catch (NoSuchAlgorithmException exception) {
            throw new ProtocolException("SHA-256 is not available", exception);
        }
    }
}
