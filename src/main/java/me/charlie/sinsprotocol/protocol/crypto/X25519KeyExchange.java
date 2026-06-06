package me.charlie.sinsprotocol.protocol.crypto;

import me.charlie.sinsprotocol.protocol.validation.ProtocolException;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public final class X25519KeyExchange {

    private static final String ALGORITHM = "X25519";

    private X25519KeyExchange() {
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new ProtocolException("Could not generate X25519 key pair", exception);
        }
    }

    public static String encodePublicKey(PublicKey publicKey) {
        return ProtocolEncoding.encodeBase64Url(publicKey.getEncoded());
    }

    public static PublicKey decodePublicKey(String encodedPublicKey) {
        try {
            byte[] keyBytes = ProtocolEncoding.decodeBase64Url(encodedPublicKey);
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new ProtocolException("Could not decode X25519 public key", exception);
        }
    }

    public static byte[] sharedSecret(KeyPair ownKeyPair, String peerPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
            keyAgreement.init(ownKeyPair.getPrivate());
            keyAgreement.doPhase(decodePublicKey(peerPublicKey), true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new ProtocolException("Could not compute X25519 shared secret", exception);
        }
    }
}
