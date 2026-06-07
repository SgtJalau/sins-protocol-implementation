package me.charlie.sinsprotocol;

import me.charlie.sinsprotocol.client.SinsClient;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.CloseReason;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.DataResponseMessage;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;
import me.charlie.sinsprotocol.server.SinsServer;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Runnable showcase for the SINS protocol implementation.
 *
 * It runs client and server, prints every protocol packet, and shows the decrypted readings accepted by the client.
 * No network transport is used here, so the demo focuses on protocol behavior rather than socket setup.
 */
public final class SinsProtocolDemo {

    private static final Logger LOGGER = Logger.getLogger(SinsProtocolDemo.class.getName());

    private SinsProtocolDemo() {
    }

    /**
     * Starts a complete demo session with packet logging enabled.
     */
    public static void main(String[] args) {
        configureConsoleLogging();

        SinsClient client = new SinsClient(true);
        SinsServer server = new SinsServer(SinsProtocolDemo::sensorReadingFor, true);
        client.setPrettyPrintPacketLogs(true);
        server.setPrettyPrintPacketLogs(true);
        client.setColorizePacketLogs(true);
        server.setColorizePacketLogs(true);

        LOGGER.info("Starting SINS protocol demo");
        runHandshake(client, server);
        runDataExchange(client, server, 11);
        client.createClose(CloseReason.NORMAL_SHUTDOWN);
        LOGGER.info("Demo finished");
    }

    /**
     * Executes packets: HELLO, HELLO_ACK, CLIENT_AUTH and SERVER_AUTH.
     * @param client The client to run the handshake for
     * @param server The server to run the handshake for
     */
    private static void runHandshake(SinsClient client, SinsServer server) {
        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);
        ServerAuthMessage serverAuth = server.handleClientAuth(clientAuth);
        client.handleServerAuth(serverAuth);
        LOGGER.info("Handshake complete, session id: " + client.sessionId());
    }

    /**
     * Sends DATA_REQUEST messages and lets the client verify and decrypt DATA_RESPONSE messages.
     * @param client The client for the data exchange
     * @param server The server for the data exchange
     * @param requestCount the amount of data requests to exchange
     */
    private static void runDataExchange(SinsClient client, SinsServer server, int requestCount) {
        for (int index = 0; index < requestCount; index++) {
            DataRequestMessage request = client.createDataRequest();
            DataResponseMessage response = server.handleDataRequest(request);
            String reading = client.handleDataResponse(response);
            LOGGER.info("Client accepted decrypted reading: " + reading);
        }
    }

    /**
     * Provides deterministic sensor readings so the demo output is easy to follow.
     * It rotates over a set of request data packages.
     * @param requestId the request id to determine the reading for
     * @return the sensor reading for the request
     */
    private static String sensorReadingFor(long requestId) {
        return switch ((int) requestId%4) {
            case 1 -> "temperature=21.5C";
            case 2 -> "humidity=43%";
            case 3 -> "air-quality=good";
            default -> "device-status=ok";
        };
    }

    /**
     * Replaces default handlers with a simple console handler.
     * Packet JSON is colorized by ProtocolPacketLogger, while this method keeps logger configuration local to the demo.
     */
    private static void configureConsoleLogging() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);

        for (Handler handler : rootLogger.getHandlers()) {
            rootLogger.removeHandler(handler);
        }

        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.INFO);
        consoleHandler.setFormatter(new SimpleFormatter());
        rootLogger.addHandler(consoleHandler);
    }
}
