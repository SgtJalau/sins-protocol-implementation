package me.charlie.sinsprotocol.protocol.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Holds the derived session keys and lazily derives later epoch keys.
 */
public final class SessionKeys {

    private final byte[] clientFinishedKey;
    private final byte[] serverFinishedKey;
    private final List<EpochKeys> epochKeys = new ArrayList<>();

    private SessionKeys(byte[] clientFinishedKey, byte[] serverFinishedKey, EpochKeys firstEpochKeys) {
        this.clientFinishedKey = Arrays.copyOf(clientFinishedKey, clientFinishedKey.length);
        this.serverFinishedKey = Arrays.copyOf(serverFinishedKey, serverFinishedKey.length);
        this.epochKeys.add(firstEpochKeys);
    }

    /**
     * Derives finished keys and epoch 0 keys from the PSK, Diffie-Hellman secret and transcript hash.
     *
     * @param preSharedKey installed protocol PSK.
     * @param diffieHellmanSecret shared X25519 secret.
     * @param transcriptHash hash of the canonical handshake transcript.
     * @return complete session key schedule starting at epoch 0.
     */
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

    /**
     * @return copy of the client finished key.
     */
    public byte[] clientFinishedKey() {
        return Arrays.copyOf(clientFinishedKey, clientFinishedKey.length);
    }

    /**
     * @return copy of the server finished key.
     */
    public byte[] serverFinishedKey() {
        return Arrays.copyOf(serverFinishedKey, serverFinishedKey.length);
    }

    /**
     * Returns keys for the requested epoch, deriving intermediate epochs if needed.
     *
     * @param epoch requested non-negative epoch number.
     * @return key material for the requested epoch.
     */
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

    /**
     * Derives all purpose-separated keys for one epoch.
     */
    private static EpochKeys buildEpochKeys(int epoch, byte[] epochSecret) {
        return new EpochKeys(
                epoch,
                epochSecret,
                Hkdf.expand(epochSecret, "client to server MAC key", 32),
                Hkdf.expand(epochSecret, "server to client MAC key", 32),
                Hkdf.expand(epochSecret, "server DATA_RESPONSE encryption key", 32)
        );
    }
}
