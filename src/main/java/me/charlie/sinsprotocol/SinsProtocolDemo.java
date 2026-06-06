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

public final class SinsProtocolDemo {

    private static final Logger LOGGER = Logger.getLogger(SinsProtocolDemo.class.getName());

    private SinsProtocolDemo() {
    }

    public static void main(String[] args) {
        configureConsoleLogging();

        SinsClient client = new SinsClient(true);
        SinsServer server = new SinsServer(SinsProtocolDemo::sensorReadingFor, true);

        LOGGER.info("Starting SINS protocol demo");
        runHandshake(client, server);
        runDataExchange(client, server, 3);
        client.createClose(CloseReason.NORMAL_SHUTDOWN);
        LOGGER.info("Demo finished");
    }

    private static void runHandshake(SinsClient client, SinsServer server) {
        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);
        ServerAuthMessage serverAuth = server.handleClientAuth(clientAuth);
        client.handleServerAuth(serverAuth);
        LOGGER.info("Handshake complete, session id: " + client.sessionId());
    }

    private static void runDataExchange(SinsClient client, SinsServer server, int requestCount) {
        for (int index = 0; index < requestCount; index++) {
            DataRequestMessage request = client.createDataRequest();
            DataResponseMessage response = server.handleDataRequest(request);
            String reading = client.handleDataResponse(response);
            LOGGER.info("Client accepted decrypted reading: " + reading);
        }
    }

    private static String sensorReadingFor(long requestId) {
        return switch ((int) requestId) {
            case 1 -> "temperature=21.5C";
            case 2 -> "humidity=43%";
            case 3 -> "air-quality=good";
            default -> "device-status=ok";
        };
    }

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
