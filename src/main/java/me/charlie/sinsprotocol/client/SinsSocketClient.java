package me.charlie.sinsprotocol.client;

import me.charlie.sinsprotocol.protocol.message.CloseReason;
import me.charlie.sinsprotocol.protocol.message.CloseMessage;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;
import me.charlie.sinsprotocol.transport.ProtocolSocketChannel;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class SinsSocketClient {

    public static final Duration DEFAULT_SESSION_DURATION = Duration.ofMinutes(30);
    public static final Duration DEFAULT_RESPONSE_TIMEOUT = Duration.ofMinutes(30);
    public static final Duration DEFAULT_REQUEST_INTERVAL = Duration.ofSeconds(30);

    private final String host;
    private final int port;
    private final SinsClient client;
    private final SinsClientMessageReceiver messageReceiver;
    private final Duration responseTimeout;

    public SinsSocketClient(String host, int port) {
        this(host, port, new SinsClient());
    }

    public SinsSocketClient(String host, int port, SinsClient client) {
        this(host, port, client, DEFAULT_RESPONSE_TIMEOUT);
    }

    public SinsSocketClient(String host, int port, SinsClient client, Duration responseTimeout) {
        this.host = host;
        this.port = port;
        this.client = client;
        this.messageReceiver = new SinsClientMessageReceiver(client);
        this.responseTimeout = responseTimeout;
    }

    /**
     * Opens a socket, completes the handshake, requests readings and sends CLOSE before disconnecting.
     */
    public List<String> requestReadings(int requestCount) throws IOException {
        List<String> readings = new ArrayList<>();

        try (Socket socket = new Socket(host, port);
             ProtocolSocketChannel channel = new ProtocolSocketChannel(socket)) {

            if (!runHandshake(channel)) {
                return readings;
            }

            try {
                for (int index = 0; index < requestCount; index++) {
                    if (requestOneReading(channel, readings)) {
                        return readings;
                    }
                }
            } catch (RuntimeException exception) {
                sendCloseIgnoringFailure(channel, CloseReason.PROTOCOL_ERROR);
                throw exception;
            }

            sendClose(channel, CloseReason.NORMAL_SHUTDOWN);
        }

        return readings;
    }

    /**
     * Requests readings until the session duration expires, then sends CLOSE normal-shutdown.
     */
    public List<String> requestReadingsFor(Duration sessionDuration, Duration requestInterval) throws IOException {
        List<String> readings = new ArrayList<>();
        long sessionEndsAt = System.nanoTime() + sessionDuration.toNanos();

        try (Socket socket = new Socket(host, port);
             ProtocolSocketChannel channel = new ProtocolSocketChannel(socket)) {
            if (!runHandshake(channel)) {
                return readings;
            }
            try {
                while (System.nanoTime() < sessionEndsAt) {
                    if (requestOneReading(channel, readings)) {
                        return readings;
                    }
                    sleepUntilNextRequest(requestInterval);
                }
            } catch (RuntimeException exception) {
                sendCloseIgnoringFailure(channel, CloseReason.PROTOCOL_ERROR);
                throw exception;
            }
            sendClose(channel, CloseReason.NORMAL_SHUTDOWN);
        }

        return readings;
    }

    /**
     * Performs the socket-backed HELLO, HELLO_ACK, CLIENT_AUTH and SERVER_AUTH exchange.
     */
    private boolean runHandshake(ProtocolSocketChannel channel) throws IOException {
        try {
            channel.writeMessage(client.startHandshake());
            ProtocolMessage helloAck = channel.readMessage()
                    .orElseThrow(() -> new IOException("Server closed connection before HELLO_ACK"));
            Optional<ProtocolMessage> clientAuth = receiveServerMessage(helloAck);
            if (helloAck instanceof CloseMessage) {
                return false;
            }
            channel.writeMessage(clientAuth.orElseThrow(() -> new IOException("HELLO_ACK did not produce CLIENT_AUTH")));

            ProtocolMessage serverAuth = channel.readMessage()
                    .orElseThrow(() -> new IOException("Server closed connection before SERVER_AUTH"));
            receiveServerMessage(serverAuth);
            return !(serverAuth instanceof CloseMessage);
        } catch (RuntimeException | IOException exception) {
            sendCloseIgnoringFailure(channel, CloseReason.PROTOCOL_ERROR);
            throw exception;
        }
    }

    private ProtocolMessage readExpectedResponse(ProtocolSocketChannel channel) throws IOException {
        channel.setReadTimeout(responseTimeout);
        try {
            return channel.readMessage()
                    .orElseThrow(() -> new IOException("Server closed connection before DATA_RESPONSE"));
        } catch (SocketTimeoutException exception) {
            sendCloseIgnoringFailure(channel, CloseReason.TIMEOUT);
            throw new IOException("Timed out while waiting for DATA_RESPONSE", exception);
        } finally {
            channel.clearReadTimeout();
        }
    }

    private boolean requestOneReading(ProtocolSocketChannel channel, List<String> readings) throws IOException {
        DataRequestMessage request = client.createDataRequest();
        channel.writeMessage(request);
        ProtocolMessage response = readExpectedResponse(channel);
        receiveServerMessage(response);
        if (response instanceof CloseMessage) {
            return true;
        }
        readings.add(messageReceiver.lastReceivedReading());
        return false;
    }

    private void sleepUntilNextRequest(Duration requestInterval) throws IOException {
        try {
            Thread.sleep(requestInterval.toMillis());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for next DATA_REQUEST", exception);
        }
    }

    private Optional<ProtocolMessage> receiveServerMessage(ProtocolMessage message) {
        try {
            return messageReceiver.receive(message);
        } catch (RuntimeException exception) {
            throw exception;
        }
    }

    private void sendClose(ProtocolSocketChannel channel, CloseReason closeReason) throws IOException {
        channel.writeMessage(client.createClose(closeReason));
    }

    private void sendCloseIgnoringFailure(ProtocolSocketChannel channel, CloseReason closeReason) {
        try {
            channel.writeMessage(client.createCloseForFailure(closeReason));
        } catch (RuntimeException | IOException ignoredException) {
            //The peer may already be gone; the original failure remains the useful error.
        }
    }
}
