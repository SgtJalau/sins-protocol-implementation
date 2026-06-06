package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//Client request for the next sensor reading after the session reaches CONNECTED state.
public record DataRequestMessage(
        int epoch,
        String messageMac,
        long sequenceNumber,
        String sessionId,
        int version
) implements AuthenticatedProtocolMessage {

    public DataRequestMessage {
        Objects.requireNonNull(messageMac, "messageMac");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    public DataRequestMessage(String messageMac, long sequenceNumber, String sessionId) {
        this(ProtocolConstants.epochForDataSequenceNumber(sequenceNumber), messageMac, sequenceNumber, sessionId, ProtocolConstants.VERSION);
    }

    @Override
    public MessageType messageType() {
        return MessageType.DATA_REQUEST;
    }

    @Override
    public Map<String, Object> toFields() {
        return MessageFields.authenticated(
                messageType(),
                sessionId,
                sequenceNumber,
                version,
                epoch,
                messageMac
        );
    }

    //Converts decoded wire fields back into the typed data request.
    public static DataRequestMessage fromFields(Map<String, Object> fields) {
        return new DataRequestMessage(
                MessageFieldReader.requiredInt(fields, "epoch"),
                MessageFieldReader.requiredString(fields, ProtocolConstants.MESSAGE_MAC_FIELD),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
