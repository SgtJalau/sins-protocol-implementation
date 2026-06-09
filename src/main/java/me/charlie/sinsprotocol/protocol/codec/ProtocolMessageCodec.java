package me.charlie.sinsprotocol.protocol.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.CloseMessage;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.DataResponseMessage;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.MessageFieldReader;
import me.charlie.sinsprotocol.protocol.message.MessageType;
import me.charlie.sinsprotocol.protocol.message.ProtocolConstants;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Encodes and decodes protocol messages using stable JSON for transcript hashing and MAC input.
 */
public final class ProtocolMessageCodec {

    //Canonical object mapper for json, so that items are always serialized in same standard, alphabetical order, so macs match on client and server
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build();
    private static final TypeReference<Map<String, Object>> MESSAGE_FIELDS_TYPE = new TypeReference<>() {
    };

    private ProtocolMessageCodec() {
    }

    /**
     * Serializes a typed message to canonical JSON with sorted object keys.
     *
     * @param message protocol message.
     * @return compact canonical JSON.
     */
    public static String encode(ProtocolMessage message) {
        return canonicalJson(message.toFields());
    }

    /**
     * Serializes a typed message for human-readable logs while preserving sorted field order.
     *
     * @param message protocol message.
     * @return pretty-printed JSON.
     */
    public static String encodePretty(ProtocolMessage message) {
        return prettyJson(message.toFields());
    }

    /**
     * @param message protocol message.
     * @return UTF-8 canonical JSON bytes for hashing and transcript construction.
     */
    public static byte[] canonicalBytes(ProtocolMessage message) {
        return encode(message).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Returns the canonical MAC input. The msg-mac field itself is excluded by protocol design.
     *
     * @param message protocol message.
     * @return UTF-8 canonical JSON bytes without msg-mac.
     */
    public static byte[] canonicalBytesWithoutMessageMac(ProtocolMessage message) {
        Map<String, Object> fields = new LinkedHashMap<>(message.toFields());
        fields.remove(ProtocolConstants.MESSAGE_MAC_FIELD);
        return canonicalJson(fields).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Parses JSON into the concrete message type selected by the msg-type field.
     *
     * @param json received protocol JSON.
     * @return typed protocol message.
     */
    public static ProtocolMessage decode(String json) {
        Map<String, Object> fields = readFields(json);
        MessageType messageType = MessageType.valueOf(MessageFieldReader.requiredString(fields, "msg-type"));

        return switch (messageType) {
            case HELLO -> HelloMessage.fromFields(fields);
            case HELLO_ACK -> HelloAckMessage.fromFields(fields);
            case CLIENT_AUTH -> ClientAuthMessage.fromFields(fields);
            case SERVER_AUTH -> ServerAuthMessage.fromFields(fields);
            case DATA_REQUEST -> DataRequestMessage.fromFields(fields);
            case DATA_RESPONSE -> DataResponseMessage.fromFields(fields);
            case CLOSE -> CloseMessage.fromFields(fields);
        };
    }

    /**
     * Serializes field maps deterministically so both endpoints sign and hash identical bytes.
     *
     * @param fields wire fields.
     * @return compact canonical JSON.
     */
    public static String canonicalJson(Map<String, Object> fields) {
        try {
            return OBJECT_MAPPER.writeValueAsString(fields);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Could not encode protocol message", exception);
        }
    }

    /**
     * Pretty JSON is only for logging or demos. Protocol hashes and MACs must use canonicalJson.
     *
     * @param fields wire fields.
     * @return pretty-printed JSON.
     */
    public static String prettyJson(Map<String, Object> fields) {
        try {
            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(fields);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Could not encode protocol message", exception);
        }
    }

    //Jackson returns generic maps first; message records then validate required fields and types.
    private static Map<String, Object> readFields(String json) {
        try {
            return OBJECT_MAPPER.readValue(json, MESSAGE_FIELDS_TYPE);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Could not decode protocol message", exception);
        }
    }
}
