package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//Server proof that completes mutual authentication after CLIENT_AUTH was verified.
public record ServerAuthMessage(
        String authValue,
        int epoch,
        String messageMac,
        long sequenceNumber,
        String sessionId,
        int version
) implements AuthenticatedProtocolMessage {

    public ServerAuthMessage {
        Objects.requireNonNull(authValue, "authValue");
        Objects.requireNonNull(messageMac, "messageMac");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    @Override
    public MessageType messageType() {
        return MessageType.SERVER_AUTH;
    }

    @Override
    public Map<String, Object> toFields() {
        Map<String, Object> fields = MessageFields.authenticated(
                messageType(),
                sessionId,
                sequenceNumber,
                version,
                epoch,
                messageMac
        );
        fields.put("auth-value", authValue);
        return fields;
    }

    //Converts decoded wire fields back into the typed server authentication message.
    public static ServerAuthMessage fromFields(Map<String, Object> fields) {
        return new ServerAuthMessage(
                MessageFieldReader.requiredString(fields, "auth-value"),
                MessageFieldReader.requiredInt(fields, "epoch"),
                MessageFieldReader.requiredString(fields, ProtocolConstants.MESSAGE_MAC_FIELD),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
