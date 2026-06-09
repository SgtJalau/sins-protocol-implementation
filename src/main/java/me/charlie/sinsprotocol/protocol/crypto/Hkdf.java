package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * HKDF and HMAC-SHA256 helpers used by the protocol key schedule.
 */
public final class Hkdf {

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int HASH_LENGTH = 32;

    private Hkdf() {
    }

    /**
     * Performs HKDF-Extract using HMAC-SHA256.
     *
     * @param salt salt key, for example the PSK or handshake secret.
     * @param inputKeyMaterial input material, for example the Diffie-Hellman secret or transcript hash.
     * @return 32-byte pseudorandom key.
     */
    public static byte[] extract(byte[] salt, byte[] inputKeyMaterial) {
        return hmac(salt, inputKeyMaterial);
    }

    /**
     * Performs HKDF-Expand using HMAC-SHA256.
     *
     * @param pseudoRandomKey key from HKDF-Extract or previous expansion step.
     * @param info context label that separates derived keys by purpose.
     * @param length requested output length in bytes.
     * @return derived key bytes of the requested length.
     */
    public static byte[] expand(byte[] pseudoRandomKey, String info, int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("HKDF output length must be positive");
        }

        int blockCount = (int) Math.ceil((double) length / HASH_LENGTH);
        if (blockCount > 255) {
            throw new IllegalArgumentException("HKDF output length is too large");
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream(length);
        byte[] previousBlock = new byte[0];
        byte[] infoBytes = ProtocolEncoding.utf8(info);

        for (int blockIndex = 1; blockIndex <= blockCount; blockIndex++) {
            byte[] input = new byte[previousBlock.length + infoBytes.length + 1];
            System.arraycopy(previousBlock, 0, input, 0, previousBlock.length);
            System.arraycopy(infoBytes, 0, input, previousBlock.length, infoBytes.length);
            input[input.length - 1] = (byte) blockIndex;
            previousBlock = hmac(pseudoRandomKey, input);
            output.writeBytes(previousBlock);
        }

        return Arrays.copyOf(output.toByteArray(), length);
    }

    /**
     * Computes HMAC-SHA256.
     *
     * @param key MAC key.
     * @param data data to authenticate.
     * @return raw HMAC bytes.
     */
    public static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(data);
        } catch (GeneralSecurityException exception) {
            throw new ProtocolException("Could not compute HMAC-SHA256", exception);
        }
    }
}
