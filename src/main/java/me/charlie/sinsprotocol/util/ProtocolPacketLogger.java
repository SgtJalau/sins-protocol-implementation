package me.charlie.sinsprotocol.util;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ProtocolPacketLogger {

    private final String endpointName;
    private final Logger logger;
    private boolean enabled;

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
                        + ProtocolMessageCodec.encode(message)
        );
    }
}
