package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//Authenticated session termination packet used for normal shutdown and protocol errors.
public record CloseMessage(
        int epoch,
        String messageMac,
        CloseReason reason,
        long sequenceNumber,
        String sessionId,
        int version
) implements AuthenticatedProtocolMessage {

    public CloseMessage {
        Objects.requireNonNull(messageMac, "messageMac");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    @Override
    public MessageType messageType() {
        return MessageType.CLOSE;
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
        fields.put("reason", reason.wireName());
        return fields;
    }

    //Converts decoded wire fields back into the typed close message.
    public static CloseMessage fromFields(Map<String, Object> fields) {
        return new CloseMessage(
                MessageFieldReader.requiredInt(fields, "epoch"),
                MessageFieldReader.requiredString(fields, ProtocolConstants.MESSAGE_MAC_FIELD),
                CloseReason.fromWireName(MessageFieldReader.requiredString(fields, "reason")),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
