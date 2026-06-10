package me.charlie.sinsprotocol.transport;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class ProtocolSocketChannel implements AutoCloseable {

    private final Socket socket;
    private final BufferedReader reader;
    private final BufferedWriter writer;

    public ProtocolSocketChannel(Socket socket) throws IOException {
        this.socket = socket;
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
    }

    /**
     * Sets the maximum time a blocking read waits for the next packet.
     */
    public void setReadTimeout(Duration timeout) throws IOException {
        socket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
    }

    /**
     * Clears the read timeout so reads can block normally again.
     */
    public void clearReadTimeout() throws IOException {
        socket.setSoTimeout(0);
    }

    /**
     * Reads one newline-delimited JSON packet from the socket.
     */
    public Optional<ProtocolMessage> readMessage() throws IOException {
        String line = reader.readLine();
        if (line == null) {
            return Optional.empty();
        }
        return Optional.of(ProtocolMessageCodec.decode(line));
    }

    /**
     * Writes one canonical JSON packet followed by a newline.
     */
    public void writeMessage(ProtocolMessage message) throws IOException {
        writer.write(ProtocolMessageCodec.encode(message));
        writer.newLine();
        writer.flush();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
