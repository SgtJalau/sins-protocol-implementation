package me.charlie.sinsprotocol.util;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ProtocolPacketLogger {

    private static final String ANSI_BRIGHT_WHITE = "\u001B[97m";
    private static final String ANSI_RESET = "\u001B[0m";

    private final String endpointName;
    private final Logger logger;
    private boolean enabled;
    private boolean prettyPrintJson;
    private boolean colorizeJson;

    public ProtocolPacketLogger(String endpointName, boolean enabled, Logger logger) {
        this.endpointName = Objects.requireNonNull(endpointName, "endpointName");
        this.enabled = enabled;
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setPrettyPrintJson(boolean prettyPrintJson) {
        this.prettyPrintJson = prettyPrintJson;
    }

    public boolean isPrettyPrintJson() {
        return prettyPrintJson;
    }

    public void setColorizeJson(boolean colorizeJson) {
        this.colorizeJson = colorizeJson;
    }

    public boolean isColorizeJson() {
        return colorizeJson;
    }

    public void incoming(ProtocolMessage message) {
        log("IN", message);
    }

    public void outgoing(ProtocolMessage message) {
        log("OUT", message);
    }

    private void log(String direction, ProtocolMessage message) {
        if (!enabled) {
            return;
        }

        logger.log(
                Level.INFO,
                () -> endpointName + " " + direction + " " + message.messageType()
                        + System.lineSeparator()
                        + formattedJson(message)
        );
    }

    private String formattedJson(ProtocolMessage message) {
        String json;
        if (prettyPrintJson) {
            json = ProtocolMessageCodec.encodePretty(message);
        } else {
            json = ProtocolMessageCodec.encode(message);
        }

        if (colorizeJson) {
            return ANSI_BRIGHT_WHITE + json + ANSI_RESET;
        }
        return json;
    }
}
