package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.ProtocolSpec;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * X25519 Diffie-Hellman helper for handshake key exchange.
 */
public final class X25519KeyExchange {


    private X25519KeyExchange() {
    }

    /**
     * @return fresh X25519 key pair for one session.
     */
    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ProtocolSpec.KEY_EXCHANGE_ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new ProtocolException("Could not generate X25519 key pair", exception);
        }
    }

    /**
     * Encodes an X25519 public key for transmission in key-share fields.
     * @param publicKey Java public key.
     * @return Base64URL encoded X.509 public key bytes.
     */
    public static String encodePublicKey(PublicKey publicKey) {
        return ProtocolEncoding.encodeBase64Url(publicKey.getEncoded());
    }

    /**
     * Decodes a received X25519 public key share.
     * @param encodedPublicKey Base64URL encoded X.509 public key bytes.
     * @return decoded Java public key.
     */
    public static PublicKey decodePublicKey(String encodedPublicKey) {
        try {
            byte[] keyBytes = ProtocolEncoding.decodeBase64Url(encodedPublicKey);
            return KeyFactory.getInstance(ProtocolSpec.KEY_EXCHANGE_ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new ProtocolException("Could not decode X25519 public key", exception);
        }
    }

    /**
     * Computes the shared X25519 secret.
     * @param ownKeyPair local ephemeral key pair.
     * @param peerPublicKey peer public key share encoded as Base64URL.
     * @return raw Diffie-Hellman shared secret.
     */
    public static byte[] sharedSecret(KeyPair ownKeyPair, String peerPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ProtocolSpec.KEY_EXCHANGE_ALGORITHM);
            keyAgreement.init(ownKeyPair.getPrivate());
            keyAgreement.doPhase(decodePublicKey(peerPublicKey), true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new ProtocolException("Could not compute X25519 shared secret", exception);
        }
    }
}
