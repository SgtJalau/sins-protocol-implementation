package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//Client proof that it derived the same transcript-bound keys and knows the pre-shared key.
public record ClientAuthMessage(
        String authValue,
        int epoch,
        String messageMac,
        long sequenceNumber,
        String sessionId,
        int version
) implements AuthenticatedProtocolMessage {

    public ClientAuthMessage {
        Objects.requireNonNull(authValue, "authValue");
        Objects.requireNonNull(messageMac, "messageMac");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    @Override
    public MessageType messageType() {
        return MessageType.CLIENT_AUTH;
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

    //Converts decoded wire fields back into the typed client authentication message.
    public static ClientAuthMessage fromFields(Map<String, Object> fields) {
        return new ClientAuthMessage(
                MessageFieldReader.requiredString(fields, "auth-value"),
                MessageFieldReader.requiredInt(fields, "epoch"),
                MessageFieldReader.requiredString(fields, ProtocolConstants.MESSAGE_MAC_FIELD),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
