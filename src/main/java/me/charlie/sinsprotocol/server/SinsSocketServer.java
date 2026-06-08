package me.charlie.sinsprotocol.server;

import lombok.Setter;
import me.charlie.sinsprotocol.protocol.message.CloseMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.transport.ProtocolSocketChannel;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Optional;

public final class SinsSocketServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final SensorReadingProvider sensorReadingProvider;
    private final boolean showcaseLoggingEnabled;
    @Setter
    private boolean prettyPrintPacketLogs;
    @Setter
    private boolean colorizePacketLogs;

    public SinsSocketServer(int port, SensorReadingProvider sensorReadingProvider) throws IOException {
        this(port, sensorReadingProvider, false);
    }

    public SinsSocketServer(int port, SensorReadingProvider sensorReadingProvider, boolean showcaseLoggingEnabled) throws IOException {
        this.serverSocket = new ServerSocket(port);
        this.sensorReadingProvider = sensorReadingProvider;
        this.showcaseLoggingEnabled = showcaseLoggingEnabled;
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    public void serveOneClient() throws IOException {
        try (Socket socket = serverSocket.accept();
             ProtocolSocketChannel channel = new ProtocolSocketChannel(socket)) {
            SinsServer server = new SinsServer(sensorReadingProvider, showcaseLoggingEnabled);
            server.setPrettyPrintPacketLogs(prettyPrintPacketLogs);
            server.setColorizePacketLogs(colorizePacketLogs);
            SinsServerMessageReceiver messageReceiver = new SinsServerMessageReceiver(server);
            handleMessages(channel, messageReceiver);
        }
    }

    private void handleMessages(ProtocolSocketChannel channel, SinsServerMessageReceiver messageReceiver) throws IOException {
        while (true) {
            Optional<ProtocolMessage> receivedMessage = channel.readMessage();
            if (receivedMessage.isEmpty()) {
                return;
            }

            Optional<ProtocolMessage> response = messageReceiver.receive(receivedMessage.get());
            if (response.isPresent()) {
                channel.writeMessage(response.get());
            }
            if (receivedMessage.get() instanceof CloseMessage) {
                return;
            }
        }
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
    }
}
