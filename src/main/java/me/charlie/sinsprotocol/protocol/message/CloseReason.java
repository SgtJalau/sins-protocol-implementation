package me.charlie.sinsprotocol.protocol.message;

//Allowed CLOSE reason values and their exact lowercase wire names.
public enum CloseReason {
    NORMAL_SHUTDOWN("normal-shutdown"),
    AUTHENTICATION_FAILED("authentication-failed"),
    PROTOCOL_ERROR("protocol-error"),
    TIMEOUT("timeout");

    private final String wireName;

    CloseReason(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    //Parses the protocol wire value instead of the enum name because CLOSE uses lowercase hyphenated strings.
    public static CloseReason fromWireName(String wireName) {
        for (CloseReason reason : values()) {
            if (reason.wireName.equals(wireName)) {
                return reason;
            }
        }

        throw new IllegalArgumentException("Unknown close reason: " + wireName);
    }
}
