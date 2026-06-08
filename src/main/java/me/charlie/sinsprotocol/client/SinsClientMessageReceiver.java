package me.charlie.sinsprotocol.client;

import me.charlie.sinsprotocol.protocol.message.CloseMessage;
import me.charlie.sinsprotocol.protocol.message.DataResponseMessage;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;
import me.charlie.sinsprotocol.protocol.validation.ProtocolException;

import java.util.Optional;

public final class SinsClientMessageReceiver {

    private final SinsClient client;
    private String lastReceivedReading;

    public SinsClientMessageReceiver(SinsClient client) {
        this.client = client;
    }

    //Dispatches received server messages and returns the next client packet when the protocol requires one.
    public Optional<ProtocolMessage> receive(ProtocolMessage message) {
        return switch (message) {
            case HelloAckMessage helloAckMessage -> Optional.of(client.handleHelloAck(helloAckMessage));
            case ServerAuthMessage serverAuthMessage -> {
                client.handleServerAuth(serverAuthMessage);
                yield Optional.empty();
            }
            case DataResponseMessage dataResponseMessage -> {
                lastReceivedReading = client.handleDataResponse(dataResponseMessage);
                yield Optional.empty();
            }
            case CloseMessage closeMessage -> {
                client.handleServerClose(closeMessage);
                yield Optional.empty();
            }
            default -> throw new ProtocolException("Client cannot receive message type: " + message.messageType());
        };
    }

    public String lastReceivedReading() {
        return lastReceivedReading;
    }
}
