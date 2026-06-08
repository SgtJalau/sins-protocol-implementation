package me.charlie.sinsprotocol;

import me.charlie.sinsprotocol.client.SinsClient;
import me.charlie.sinsprotocol.client.SinsSocketClient;
import me.charlie.sinsprotocol.server.SinsSocketServer;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Runnable showcase for the SINS protocol implementation.
 *
 * It starts a local TCP server, connects a client socket, prints every protocol packet,
 * and shows the decrypted readings accepted by the client.
 */
public final class SinsProtocolDemo {

    private static final Logger LOGGER = Logger.getLogger(SinsProtocolDemo.class.getName());

    private SinsProtocolDemo() {
    }

    /**
     * Starts a complete socket-backed demo session with packet logging enabled.
     */
    public static void main(String[] args) throws Exception {
        configureConsoleLogging();

        try (SinsSocketServer server = new SinsSocketServer(0, SinsProtocolDemo::sensorReadingFor, true)) {
            server.setPrettyPrintPacketLogs(true);
            server.setColorizePacketLogs(true);

            AtomicReference<Exception> serverFailure = new AtomicReference<>();
            Thread serverThread = startServerThread(server, serverFailure);

            SinsClient client = new SinsClient(true);
            client.setPrettyPrintPacketLogs(true);
            client.setColorizePacketLogs(true);

            LOGGER.info("Starting SINS protocol socket demo on port " + server.port());
            SinsSocketClient socketClient = new SinsSocketClient("localhost", server.port(), client);
            List<String> readings = socketClient.requestReadings(3);
            serverThread.join(5_000);

            if (serverFailure.get() != null) {
                throw serverFailure.get();
            }

            readings.forEach(reading -> LOGGER.info("Client accepted decrypted reading: " + reading));
            LOGGER.info("Demo finished");
        }
    }

    /**
     * Runs the server on a background thread so the client can connect over localhost.
     */
    private static Thread startServerThread(SinsSocketServer server, AtomicReference<Exception> serverFailure) {
        Thread serverThread = new Thread(() -> {
            try {
                server.serveOneClient();
            } catch (Exception exception) {
                serverFailure.set(exception);
            }
        });
        serverThread.start();
        return serverThread;
    }

    /**
     * Provides deterministic sensor readings so the demo output is easy to follow.
     */
    private static String sensorReadingFor(long requestId) {
        return switch ((int) requestId) {
            case 1 -> "temperature=21.5C";
            case 2 -> "humidity=43%";
            case 3 -> "air-quality=good";
            default -> "device-status=ok";
        };
    }

    /**
     * Replaces default handlers with a simple console handler.
     *
     * Packet JSON is colorized by ProtocolPacketLogger, while this method keeps logger
     * configuration local to the demo.
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
