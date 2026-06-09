package me.charlie.sinsprotocol.client;

import me.charlie.sinsprotocol.protocol.message.CloseReason;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.transport.ProtocolSocketChannel;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public final class SinsSocketClient {

    private final String host;
    private final int port;
    private final SinsClient client;
    private final SinsClientMessageReceiver messageReceiver;

    public SinsSocketClient(String host, int port) {
        this(host, port, new SinsClient());
    }

    public SinsSocketClient(String host, int port, SinsClient client) {
        this.host = host;
        this.port = port;
        this.client = client;
        this.messageReceiver = new SinsClientMessageReceiver(client);
    }

    /**
     * Opens a socket, completes the handshake, requests readings and sends CLOSE before disconnecting.
     */
    public List<String> requestReadings(int requestCount) throws IOException {
        List<String> readings = new ArrayList<>();

        try (Socket socket = new Socket(host, port);
             ProtocolSocketChannel channel = new ProtocolSocketChannel(socket)) {
            runHandshake(channel);
            for (int index = 0; index < requestCount; index++) {
                DataRequestMessage request = client.createDataRequest();
                channel.writeMessage(request);
                ProtocolMessage response = channel.readMessage()
                        .orElseThrow(() -> new IOException("Server closed connection before DATA_RESPONSE"));
                messageReceiver.receive(response);
                readings.add(messageReceiver.lastReceivedReading());
            }
            channel.writeMessage(client.createClose(CloseReason.NORMAL_SHUTDOWN));
        }

        return readings;
    }

    /**
     * Performs the socket-backed HELLO, HELLO_ACK, CLIENT_AUTH and SERVER_AUTH exchange.
     */
    private void runHandshake(ProtocolSocketChannel channel) throws IOException {
        channel.writeMessage(client.startHandshake());
        ProtocolMessage helloAck = channel.readMessage()
                .orElseThrow(() -> new IOException("Server closed connection before HELLO_ACK"));
        ProtocolMessage clientAuth = messageReceiver.receive(helloAck)
                .orElseThrow(() -> new IOException("HELLO_ACK did not produce CLIENT_AUTH"));
        channel.writeMessage(clientAuth);

        ProtocolMessage serverAuth = channel.readMessage()
                .orElseThrow(() -> new IOException("Server closed connection before SERVER_AUTH"));
        messageReceiver.receive(serverAuth);
    }
}
