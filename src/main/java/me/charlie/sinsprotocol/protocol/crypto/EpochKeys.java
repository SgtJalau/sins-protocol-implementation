package me.charlie.sinsprotocol.protocol.crypto;

import java.util.Arrays;

/**
 * Key material for one protocol epoch.
 *
 * Copies are made on construction and access so callers cannot accidentally mutate session key material.
 */
public record EpochKeys(
        int epoch,
        byte[] epochSecret,
        byte[] clientMacKey,
        byte[] serverMacKey,
        byte[] serverEncryptionKey
) {

    /**
     * Stores defensive copies of all key arrays.
     */
    public EpochKeys {
        epochSecret = Arrays.copyOf(epochSecret, epochSecret.length);
        clientMacKey = Arrays.copyOf(clientMacKey, clientMacKey.length);
        serverMacKey = Arrays.copyOf(serverMacKey, serverMacKey.length);
        serverEncryptionKey = Arrays.copyOf(serverEncryptionKey, serverEncryptionKey.length);
    }

    /**
     * @return copy of the epoch secret used to derive the next epoch.
     */
    @Override
    public byte[] epochSecret() {
        return Arrays.copyOf(epochSecret, epochSecret.length);
    }

    /**
     * @return copy of the client-to-server MAC key.
     */
    @Override
    public byte[] clientMacKey() {
        return Arrays.copyOf(clientMacKey, clientMacKey.length);
    }

    /**
     * @return copy of the server-to-client MAC key.
     */
    @Override
    public byte[] serverMacKey() {
        return Arrays.copyOf(serverMacKey, serverMacKey.length);
    }

    /**
     * @return copy of the server DATA_RESPONSE encryption key.
     */
    @Override
    public byte[] serverEncryptionKey() {
        return Arrays.copyOf(serverEncryptionKey, serverEncryptionKey.length);
    }
}
