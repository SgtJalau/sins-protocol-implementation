package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;
import java.util.Objects;

//Server response carrying one encrypted sensor reading for a validated DATA_REQUEST.
public record DataResponseMessage(
        EncryptedData encryptedData,
        int epoch,
        String messageMac,
        long sequenceNumber,
        String sessionId,
        int version
) implements AuthenticatedProtocolMessage {

    public DataResponseMessage {
        Objects.requireNonNull(encryptedData, "encryptedData");
        Objects.requireNonNull(messageMac, "messageMac");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    public DataResponseMessage(EncryptedData encryptedData, String messageMac, long sequenceNumber, String sessionId) {
        this(
                encryptedData,
                ProtocolConstants.epochForDataSequenceNumber(sequenceNumber),
                messageMac,
                sequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
    }

    @Override
    public MessageType messageType() {
        return MessageType.DATA_RESPONSE;
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
        fields.put("encrypted-data", encryptedData.toFields());
        return fields;
    }

    //Converts decoded wire fields back into the typed encrypted data response.
    public static DataResponseMessage fromFields(Map<String, Object> fields) {
        return new DataResponseMessage(
                EncryptedData.fromFields(MessageFieldReader.requiredObject(fields, "encrypted-data")),
                MessageFieldReader.requiredInt(fields, "epoch"),
                MessageFieldReader.requiredString(fields, ProtocolConstants.MESSAGE_MAC_FIELD),
                MessageFieldReader.requiredLong(fields, "sequence-number"),
                MessageFieldReader.requiredString(fields, "session-id"),
                MessageFieldReader.requiredInt(fields, "version")
        );
    }
}
