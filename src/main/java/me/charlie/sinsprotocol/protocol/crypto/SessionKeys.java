package me.charlie.sinsprotocol.protocol.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class SessionKeys {

    private final byte[] clientFinishedKey;
    private final byte[] serverFinishedKey;
    private final List<EpochKeys> epochKeys = new ArrayList<>();

    private SessionKeys(byte[] clientFinishedKey, byte[] serverFinishedKey, EpochKeys firstEpochKeys) {
        this.clientFinishedKey = Arrays.copyOf(clientFinishedKey, clientFinishedKey.length);
        this.serverFinishedKey = Arrays.copyOf(serverFinishedKey, serverFinishedKey.length);
        this.epochKeys.add(firstEpochKeys);
    }

    public static SessionKeys derive(byte[] preSharedKey, byte[] diffieHellmanSecret, byte[] transcriptHash) {
        byte[] handshakeSecret = Hkdf.extract(preSharedKey, diffieHellmanSecret);
        byte[] masterSecret = Hkdf.extract(handshakeSecret, transcriptHash);
        byte[] epochSecret = Hkdf.expand(masterSecret, "epoch secret 0", 32);

        return new SessionKeys(
                Hkdf.expand(masterSecret, "client finished key", 32),
                Hkdf.expand(masterSecret, "server finished key", 32),
                buildEpochKeys(0, epochSecret)
        );
    }

    public byte[] clientFinishedKey() {
        return Arrays.copyOf(clientFinishedKey, clientFinishedKey.length);
    }

    public byte[] serverFinishedKey() {
        return Arrays.copyOf(serverFinishedKey, serverFinishedKey.length);
    }

    public EpochKeys epoch(int epoch) {
        if (epoch < 0) {
            throw new IllegalArgumentException("Epoch must not be negative");
        }

        while (epochKeys.size() <= epoch) {
            EpochKeys previous = epochKeys.getLast();
            byte[] nextEpochSecret = Hkdf.expand(previous.epochSecret(), "next epoch secret", 32);
            epochKeys.add(buildEpochKeys(previous.epoch() + 1, nextEpochSecret));
        }

        return epochKeys.get(epoch);
    }

    private static EpochKeys buildEpochKeys(int epoch, byte[] epochSecret) {
        return new EpochKeys(
                epoch,
                epochSecret,
                Hkdf.expand(epochSecret, "client to server MAC key", 32),
                Hkdf.expand(epochSecret, "server to client MAC key", 32),
                Hkdf.expand(epochSecret, "server DATA_RESPONSE encryption key", 32),
                Hkdf.expand(epochSecret, "server DATA_RESPONSE IV", 12)
        );
    }
}
