package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;

//Validates generic Jackson field maps before converting them into typed message records.
public final class MessageFieldReader {

    private MessageFieldReader() {
    }

    //Reads required protocol strings such as session-id, auth-value and encoded key shares.
    public static String requiredString(Map<String, Object> fields, String fieldName) {
        Object value = required(fields, fieldName);
        if (value instanceof String stringValue) {
            return stringValue;
        }

        throw new IllegalArgumentException("Field '" + fieldName + "' must be a string");
    }

    //Reads compact numeric fields that must fit into Java int, for example version and epoch.
    public static int requiredInt(Map<String, Object> fields, String fieldName) {
        long value = requiredLong(fields, fieldName);
        return Math.toIntExact(value);
    }

    //Reads sequence identifiers without silently accepting missing or non-numeric values.
    public static long requiredLong(Map<String, Object> fields, String fieldName) {
        Object value = required(fields, fieldName);
        if (value instanceof Number numberValue) {
            return numberValue.longValue();
        }

        throw new IllegalArgumentException("Field '" + fieldName + "' must be a number");
    }

    //Reads nested JSON objects such as encrypted-data.
    @SuppressWarnings("unchecked")
    public static Map<String, Object> requiredObject(Map<String, Object> fields, String fieldName) {
        Object value = required(fields, fieldName);
        if (value instanceof Map<?, ?> mapValue) {
            return (Map<String, Object>) mapValue;
        }

        throw new IllegalArgumentException("Field '" + fieldName + "' must be an object");
    }

    private static Object required(Map<String, Object> fields, String fieldName) {
        Object value = fields.get(fieldName);
        if (value == null) {
            throw new IllegalArgumentException("Missing field: " + fieldName);
        }

        return value;
    }
}
