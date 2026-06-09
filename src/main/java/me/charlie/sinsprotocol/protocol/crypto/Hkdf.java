package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class Hkdf {

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int HASH_LENGTH = 32;

    private Hkdf() {
    }

    public static byte[] extract(byte[] salt, byte[] inputKeyMaterial) {
        return hmac(salt, inputKeyMaterial);
    }

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
