package me.charlie.sinsprotocol.protocol.message;

import java.util.LinkedHashMap;
import java.util.Map;

//Small factory for shared wire fields so every message uses the same names and numeric types.
final class MessageFields {

    private MessageFields() {
    }

    //Creates fields present on every protocol message before message-specific values are added.
    static Map<String, Object> base(MessageType messageType, String sessionId, long sequenceNumber, int version) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("msg-type", messageType.name());
        fields.put("sequence-number", sequenceNumber);
        fields.put("session-id", sessionId);
        fields.put("version", version);
        return fields;
    }

    //Creates the common authenticated-message fields including epoch and msg-mac.
    static Map<String, Object> authenticated(
            MessageType messageType,
            String sessionId,
            long sequenceNumber,
            int version,
            int epoch,
            String messageMac
    ) {
        Map<String, Object> fields = base(messageType, sessionId, sequenceNumber, version);
        fields.put("epoch", epoch);
        fields.put(ProtocolConstants.MESSAGE_MAC_FIELD, messageMac);
        return fields;
    }
}
