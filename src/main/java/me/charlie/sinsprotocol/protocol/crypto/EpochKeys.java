package me.charlie.sinsprotocol.protocol.crypto;

import java.util.Arrays;

public record EpochKeys(
        int epoch,
        byte[] epochSecret,
        byte[] clientMacKey,
        byte[] serverMacKey,
        byte[] serverEncryptionKey,
        byte[] serverIv
) {

    public EpochKeys {
        epochSecret = Arrays.copyOf(epochSecret, epochSecret.length);
        clientMacKey = Arrays.copyOf(clientMacKey, clientMacKey.length);
        serverMacKey = Arrays.copyOf(serverMacKey, serverMacKey.length);
        serverEncryptionKey = Arrays.copyOf(serverEncryptionKey, serverEncryptionKey.length);
        serverIv = Arrays.copyOf(serverIv, serverIv.length);
    }

    @Override
    public byte[] epochSecret() {
        return Arrays.copyOf(epochSecret, epochSecret.length);
    }

    @Override
    public byte[] clientMacKey() {
        return Arrays.copyOf(clientMacKey, clientMacKey.length);
    }

    @Override
    public byte[] serverMacKey() {
        return Arrays.copyOf(serverMacKey, serverMacKey.length);
    }

    @Override
    public byte[] serverEncryptionKey() {
        return Arrays.copyOf(serverEncryptionKey, serverEncryptionKey.length);
    }

    @Override
    public byte[] serverIv() {
        return Arrays.copyOf(serverIv, serverIv.length);
    }
}
