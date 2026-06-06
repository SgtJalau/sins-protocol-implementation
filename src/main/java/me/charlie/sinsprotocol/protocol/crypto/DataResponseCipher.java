package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.EncryptedData;
import me.charlie.sinsprotocol.protocol.message.MessageType;
import me.charlie.sinsprotocol.protocol.validation.ProtocolException;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class DataResponseCipher {

    private static final int AUTHENTICATION_TAG_BITS = 128;
    private static final int AUTHENTICATION_TAG_BYTES = AUTHENTICATION_TAG_BITS / Byte.SIZE;

    private DataResponseCipher() {
    }

    public static EncryptedData encrypt(
            byte[] encryptionKey,
            int epoch,
            long requestId,
            long sequenceNumber,
            String sessionId,
            int version,
            String plaintext
    ) {
        byte[] nonce = ProtocolEncoding.dataResponseNonce(epoch, sequenceNumber);
        byte[] encrypted = runCipher(
                Cipher.ENCRYPT_MODE,
                encryptionKey,
                nonce,
                associatedData(epoch, requestId, sequenceNumber, sessionId, version),
                plaintext.getBytes(StandardCharsets.UTF_8)
        );
        int ciphertextEnd = encrypted.length - AUTHENTICATION_TAG_BYTES;
        byte[] ciphertext = Arrays.copyOf(encrypted, ciphertextEnd);
        byte[] tag = Arrays.copyOfRange(encrypted, ciphertextEnd, encrypted.length);

        return new EncryptedData(
                ProtocolEncoding.encodeBase64Url(ciphertext),
                ProtocolEncoding.encodeBase64Url(nonce),
                ProtocolEncoding.encodeBase64Url(tag)
        );
    }

    public static String decrypt(
            byte[] encryptionKey,
            int epoch,
            long requestId,
            long sequenceNumber,
            String sessionId,
            int version,
            EncryptedData encryptedData
    ) {
        byte[] ciphertext = ProtocolEncoding.decodeBase64Url(encryptedData.ciphertext());
        byte[] tag = ProtocolEncoding.decodeBase64Url(encryptedData.tag());
        byte[] receivedNonce = ProtocolEncoding.decodeBase64Url(encryptedData.nonce());
        byte[] expectedNonce = ProtocolEncoding.dataResponseNonce(epoch, sequenceNumber);
        if (!Arrays.equals(expectedNonce, receivedNonce)) {
            throw new ProtocolException("Invalid DATA_RESPONSE nonce");
        }

        byte[] encrypted = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, encrypted, 0, ciphertext.length);
        System.arraycopy(tag, 0, encrypted, ciphertext.length, tag.length);

        try {
            byte[] plaintext = runCipher(
                    Cipher.DECRYPT_MODE,
                    encryptionKey,
                    receivedNonce,
                    associatedData(epoch, requestId, sequenceNumber, sessionId, version),
                    encrypted
            );
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (ProtocolException exception) {
            if (exception.getCause() instanceof AEADBadTagException) {
                throw new ProtocolException("Invalid DATA_RESPONSE authentication tag", exception);
            }
            throw exception;
        }
    }

    //AAD binds the encrypted bytes to the visible DATA_RESPONSE header.
    private static byte[] associatedData(int epoch, long requestId, long sequenceNumber, String sessionId, int version) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("epoch", epoch);
        fields.put("msg-type", MessageType.DATA_RESPONSE.name());
        fields.put("request-id", requestId);
        fields.put("sequence-number", sequenceNumber);
        fields.put("session-id", sessionId);
        fields.put("version", version);
        return ProtocolEncoding.utf8(ProtocolMessageCodec.canonicalJson(fields));
    }

    private static byte[] runCipher(int mode, byte[] key, byte[] nonce, byte[] associatedData, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AUTHENTICATION_TAG_BITS, nonce));
            cipher.updateAAD(associatedData);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException exception) {
            throw new ProtocolException("Could not process DATA_RESPONSE encryption", exception);
        }
    }
}
