package me.charlie.sinsprotocol.transport;

import me.charlie.sinsprotocol.protocol.codec.ProtocolMessageCodec;
import me.charlie.sinsprotocol.protocol.message.ProtocolMessage;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
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

    public Optional<ProtocolMessage> readMessage() throws IOException {
        String line = reader.readLine();
        if (line == null) {
            return Optional.empty();
        }
        return Optional.of(ProtocolMessageCodec.decode(line));
    }

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
