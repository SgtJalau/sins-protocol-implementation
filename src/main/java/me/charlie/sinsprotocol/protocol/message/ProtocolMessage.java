package me.charlie.sinsprotocol.protocol.message;

import java.util.Map;

//Common contract for all protocol packets that can be sent over the transport.
public sealed interface ProtocolMessage permits
        HelloMessage,
        HelloAckMessage,
        AuthenticatedProtocolMessage {

    MessageType messageType();

    String sessionId();

    long sequenceNumber();

    int version();

    //Returns the exact wire field names used by the canonical codec, including hyphenated names.
    Map<String, Object> toFields();
}
