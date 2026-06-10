package me.charlie.sinsprotocol.server;

import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.CloseMessage;
import me.charlie.sinsprotocol.protocol.message.CloseReason;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;

import java.util.Optional;

public final class SinsServerMessageReceiver {

    private final SinsServer server;

    public SinsServerMessageReceiver(SinsServer server) {
        this.server = server;
    }

    /**
     * Dispatches a received client message and returns the server response packet when one is required.
     */
    public Optional<ProtocolMessage> receive(ProtocolMessage message) {
        return switch (message) {
            case HelloMessage helloMessage -> Optional.of(server.handleHello(helloMessage));
            case ClientAuthMessage clientAuthMessage -> Optional.of(server.handleClientAuth(clientAuthMessage));
            case DataRequestMessage dataRequestMessage -> Optional.of(server.handleDataRequest(dataRequestMessage));
            case CloseMessage closeMessage -> {
                server.handleClientClose(closeMessage);
                yield Optional.empty();
            }
            default -> throw new ProtocolException("Server cannot receive message type: " + message.messageType());
        };
    }

    public CloseMessage createCloseForFailure(CloseReason closeReason, ProtocolMessage receivedMessage) {
        return server.createCloseForFailure(closeReason, receivedMessage);
    }
}
