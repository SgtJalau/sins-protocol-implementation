package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//First client handshake packet containing the client X25519 key share and nonce.
public record HelloMessage(
        String clientKeyShare,
        String nonceC,
        long sequenceNumber,
        String sessionId,
        int version
) implements ProtocolMessage {

    public HelloMessage {
        Objects.requireNonNull(clientKeyShare, "clientKeyShare");
        Objects.requireNonNull(nonceC, "nonceC");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    @Override
    public MessageType messageType() {
        return MessageType.HELLO;
    }

    @Override
    public Map<String, Object> toFields() {
        Map<String, Object> fields = MessageFields.base(messageType(), sessionId, sequenceNumber, version);
        fields.put("client-key-share", clientKeyShare);
        fields.put("nonce-c", nonceC);
        return fields;
    }

    //Converts decoded wire fields back into the typed handshake message.
    public static HelloMessage fromFields(Map<String, Object> fields) {
        return new HelloMessage(
                MessageFieldReader.requiredString(fields, "client-key-share"),
                MessageFieldReader.requiredString(fields, "nonce-c"),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
