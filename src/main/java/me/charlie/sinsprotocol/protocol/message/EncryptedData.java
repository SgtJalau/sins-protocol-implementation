package me.charlie.sinsprotocol.protocol.message;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

//AES-GCM result embedded in DATA_RESPONSE as encrypted-data.
public record EncryptedData(
        String ciphertext,
        String nonce,
        String tag
) {

    public EncryptedData {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(tag, "tag");
    }

    public Map<String, Object> toFields() {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("ciphertext", ciphertext);
        fields.put("nonce", nonce);
        fields.put("tag", tag);
        return fields;
    }

    //Rebuilds the nested encrypted-data object after Jackson parsed the JSON into generic maps.
    public static EncryptedData fromFields(Map<String, Object> fields) {
        return new EncryptedData(
                MessageFieldReader.requiredString(fields, "ciphertext"),
                MessageFieldReader.requiredString(fields, "nonce"),
                MessageFieldReader.requiredString(fields, "tag")
        );
    }
}
