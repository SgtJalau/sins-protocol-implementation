package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//Server handshake response containing the server X25519 key share and nonce.
public record HelloAckMessage(
        String nonceS,
        String serverKeyShare,
        long sequenceNumber,
        String sessionId,
        int version
) implements ProtocolMessage {

    public HelloAckMessage {
        Objects.requireNonNull(nonceS, "nonceS");
        Objects.requireNonNull(serverKeyShare, "serverKeyShare");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    public HelloAckMessage(String nonceS, String serverKeyShare, String sessionId) {
        this(nonceS, serverKeyShare, ProtocolConstants.FIRST_SEQUENCE_NUMBER, sessionId, ProtocolConstants.VERSION);
    }

    @Override
    public MessageType messageType() {
        return MessageType.HELLO_ACK;
    }

    @Override
    public Map<String, Object> toFields() {
        Map<String, Object> fields = MessageFields.base(messageType(), sessionId, sequenceNumber, version);
        fields.put("nonce-s", nonceS);
        fields.put("server-key-share", serverKeyShare);
        return fields;
    }

    //Converts decoded wire fields back into the typed server handshake response.
    public static HelloAckMessage fromFields(Map<String, Object> fields) {
        return new HelloAckMessage(
                MessageFieldReader.requiredString(fields, "nonce-s"),
                MessageFieldReader.requiredString(fields, "server-key-share"),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
