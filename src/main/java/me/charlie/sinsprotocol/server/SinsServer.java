package me.charlie.sinsprotocol.server;

import me.charlie.sinsprotocol.client.SinsClient;
import me.charlie.sinsprotocol.protocol.crypto.DataResponseCipher;
import me.charlie.sinsprotocol.protocol.crypto.EpochKeys;
import me.charlie.sinsprotocol.protocol.crypto.MessageAuthentication;
import me.charlie.sinsprotocol.protocol.crypto.ProtocolEncoding;
import me.charlie.sinsprotocol.protocol.crypto.SessionKeys;
import me.charlie.sinsprotocol.protocol.crypto.TranscriptHash;
import me.charlie.sinsprotocol.protocol.crypto.X25519KeyExchange;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.CloseMessage;
import me.charlie.sinsprotocol.protocol.message.CloseReason;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.DataResponseMessage;
import me.charlie.sinsprotocol.protocol.message.EncryptedData;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolConstants;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;
import me.charlie.sinsprotocol.protocol.validation.ProtocolException;
import me.charlie.sinsprotocol.util.ProtocolPacketLogger;

import java.security.KeyPair;
import java.util.Objects;
import java.util.logging.Logger;

public final class SinsServer {

    private static final Logger LOGGER = Logger.getLogger(SinsServer.class.getName());

    private final byte[] preSharedKey;
    private final SensorReadingProvider sensorReadingProvider;
    private final ProtocolPacketLogger packetLogger;
    private KeyPair keyPair;
    private HelloMessage helloMessage;
    private HelloAckMessage helloAckMessage;
    private SessionKeys sessionKeys;
    private ServerState state = ServerState.NEW;
    private long nextClientSequenceNumber = 1;
    private long nextServerSequenceNumber = 1;
    private String sessionId;

    public SinsServer(SensorReadingProvider sensorReadingProvider) {
        this(SinsClient.SENSOR_PRE_SHARED_KEY, sensorReadingProvider, false);
    }

    public SinsServer(SensorReadingProvider sensorReadingProvider, boolean showcaseLoggingEnabled) {
        this(SinsClient.SENSOR_PRE_SHARED_KEY, sensorReadingProvider, showcaseLoggingEnabled);
    }

    public SinsServer(String preSharedKey, SensorReadingProvider sensorReadingProvider) {
        this(preSharedKey, sensorReadingProvider, false);
    }

    public SinsServer(String preSharedKey, SensorReadingProvider sensorReadingProvider, boolean showcaseLoggingEnabled) {
        this.preSharedKey = ProtocolEncoding.utf8(Objects.requireNonNull(preSharedKey, "preSharedKey"));
        this.sensorReadingProvider = Objects.requireNonNull(sensorReadingProvider, "sensorReadingProvider");
        this.packetLogger = new ProtocolPacketLogger("SERVER", showcaseLoggingEnabled, LOGGER);
    }

    public void setShowcaseLoggingEnabled(boolean showcaseLoggingEnabled) {
        packetLogger.setEnabled(showcaseLoggingEnabled);
    }

    public boolean isShowcaseLoggingEnabled() {
        return packetLogger.isEnabled();
    }

    public void setPrettyPrintPacketLogs(boolean prettyPrintPacketLogs) {
        packetLogger.setPrettyPrintJson(prettyPrintPacketLogs);
    }

    public void setColorizePacketLogs(boolean colorizePacketLogs) {
        packetLogger.setColorizeJson(colorizePacketLogs);
    }

    //Accepts a new HELLO and returns HELLO_ACK with the server key share.
    public HelloAckMessage handleHello(HelloMessage receivedHelloMessage) {
        packetLogger.incoming(receivedHelloMessage);
        requireState(ServerState.NEW);
        validateVersion(receivedHelloMessage.version());
        validateSequence(receivedHelloMessage.sequenceNumber(), nextClientSequenceNumber, "client");

        helloMessage = receivedHelloMessage;
        sessionId = receivedHelloMessage.sessionId();
        nextClientSequenceNumber++;
        keyPair = X25519KeyExchange.generateKeyPair();
        helloAckMessage = new HelloAckMessage(
                ProtocolEncoding.randomBase64Url(32),
                X25519KeyExchange.encodePublicKey(keyPair.getPublic()),
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        nextServerSequenceNumber++;

        byte[] sharedSecret = X25519KeyExchange.sharedSecret(keyPair, receivedHelloMessage.clientKeyShare());
        byte[] transcriptHash = TranscriptHash.initial(receivedHelloMessage, helloAckMessage);
        sessionKeys = SessionKeys.derive(preSharedKey, sharedSecret, transcriptHash);
        state = ServerState.WAITING_FOR_CLIENT_AUTH;
        packetLogger.outgoing(helloAckMessage);
        return helloAckMessage;
    }

    //Verifies CLIENT_AUTH and returns SERVER_AUTH to complete mutual authentication.
    public ServerAuthMessage handleClientAuth(ClientAuthMessage clientAuthMessage) {
        packetLogger.incoming(clientAuthMessage);
        requireState(ServerState.WAITING_FOR_CLIENT_AUTH);
        validateSession(clientAuthMessage.sessionId(), clientAuthMessage.version());
        validateSequence(clientAuthMessage.sequenceNumber(), nextClientSequenceNumber, "client");
        validateEpoch(clientAuthMessage.epoch(), 0);

        EpochKeys epochKeys = sessionKeys.epoch(0);
        MessageAuthentication.verifyMessageMac(epochKeys.clientMacKey(), clientAuthMessage, clientAuthMessage.messageMac());
        byte[] initialTranscriptHash = TranscriptHash.initial(helloMessage, helloAckMessage);
        MessageAuthentication.verifyAuthenticationValue(
                sessionKeys.clientFinishedKey(),
                initialTranscriptHash,
                clientAuthMessage.authValue()
        );

        byte[] serverTranscriptHash = TranscriptHash.withClientAuth(helloMessage, helloAckMessage, clientAuthMessage);
        String authValue = MessageAuthentication.hmacBase64Url(sessionKeys.serverFinishedKey(), serverTranscriptHash);
        ServerAuthMessage unsignedServerAuthMessage = new ServerAuthMessage(
                authValue,
                0,
                "",
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        String messageMac = MessageAuthentication.messageMac(epochKeys.serverMacKey(), unsignedServerAuthMessage);
        ServerAuthMessage serverAuthMessage = new ServerAuthMessage(
                authValue,
                0,
                messageMac,
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );

        nextClientSequenceNumber++;
        nextServerSequenceNumber++;
        state = ServerState.CONNECTED;
        packetLogger.outgoing(serverAuthMessage);
        return serverAuthMessage;
    }

    //Validates DATA_REQUEST and returns one encrypted DATA_RESPONSE.
    public DataResponseMessage handleDataRequest(DataRequestMessage dataRequestMessage) {
        packetLogger.incoming(dataRequestMessage);
        requireState(ServerState.CONNECTED);
        validateSession(dataRequestMessage.sessionId(), dataRequestMessage.version());
        validateSequence(dataRequestMessage.sequenceNumber(), nextClientSequenceNumber, "client");
        int expectedEpoch = ProtocolConstants.epochForDataSequenceNumber(dataRequestMessage.sequenceNumber());
        validateEpoch(dataRequestMessage.epoch(), expectedEpoch);

        EpochKeys requestEpochKeys = sessionKeys.epoch(dataRequestMessage.epoch());
        MessageAuthentication.verifyMessageMac(
                requestEpochKeys.clientMacKey(),
                dataRequestMessage,
                dataRequestMessage.messageMac()
        );

        long requestId = requestIdFor(dataRequestMessage.sequenceNumber());
        int responseEpoch = ProtocolConstants.epochForDataSequenceNumber(nextServerSequenceNumber);
        EpochKeys responseEpochKeys = sessionKeys.epoch(responseEpoch);
        EncryptedData encryptedData = DataResponseCipher.encrypt(
                responseEpochKeys.serverEncryptionKey(),
                responseEpoch,
                requestId,
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION,
                sensorReadingProvider.nextReading(requestId)
        );
        DataResponseMessage unsignedResponse = new DataResponseMessage(
                encryptedData,
                responseEpoch,
                "",
                requestId,
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        String messageMac = MessageAuthentication.messageMac(responseEpochKeys.serverMacKey(), unsignedResponse);
        DataResponseMessage dataResponseMessage = new DataResponseMessage(
                encryptedData,
                responseEpoch,
                messageMac,
                requestId,
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );

        nextClientSequenceNumber++;
        nextServerSequenceNumber++;
        packetLogger.outgoing(dataResponseMessage);
        return dataResponseMessage;
    }

    public CloseMessage createClose(CloseReason closeReason) {
        requireConnectedOrHandshake();
        int epoch = closeEpoch(nextServerSequenceNumber);
        CloseMessage unsignedCloseMessage = new CloseMessage(
                epoch,
                "",
                closeReason,
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        String messageMac = MessageAuthentication.messageMac(sessionKeys.epoch(epoch).serverMacKey(), unsignedCloseMessage);
        CloseMessage closeMessage = new CloseMessage(
                epoch,
                messageMac,
                closeReason,
                nextServerSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        nextServerSequenceNumber++;
        state = ServerState.CLOSED;
        packetLogger.outgoing(closeMessage);
        return closeMessage;
    }

    public boolean isConnected() {
        return state == ServerState.CONNECTED;
    }

    public String sessionId() {
        return sessionId;
    }

    private void validateSession(String receivedSessionId, int version) {
        if (!Objects.equals(sessionId, receivedSessionId)) {
            throw new ProtocolException("Session id does not match");
        }
        validateVersion(version);
    }

    private void validateVersion(int version) {
        if (version != ProtocolConstants.VERSION) {
            throw new ProtocolException("Unsupported protocol version: " + version);
        }
    }

    private void validateSequence(long receivedSequenceNumber, long expectedSequenceNumber, String sender) {
        if (receivedSequenceNumber != expectedSequenceNumber) {
            throw new ProtocolException("Unexpected " + sender + " sequence number");
        }
    }

    private void validateEpoch(int receivedEpoch, int expectedEpoch) {
        if (receivedEpoch != expectedEpoch) {
            throw new ProtocolException("Unexpected epoch");
        }
    }

    private void requireState(ServerState expectedState) {
        if (state != expectedState) {
            throw new ProtocolException("Server is in state " + state + " but expected " + expectedState);
        }
    }

    private void requireConnectedOrHandshake() {
        if (state != ServerState.CONNECTED && state != ServerState.WAITING_FOR_CLIENT_AUTH) {
            throw new ProtocolException("Server cannot close from state " + state);
        }
    }

    private long requestIdFor(long sequenceNumber) {
        return sequenceNumber - 2;
    }

    private int closeEpoch(long sequenceNumber) {
        if (sequenceNumber < ProtocolConstants.FIRST_DATA_SEQUENCE_NUMBER) {
            return 0;
        }
        return ProtocolConstants.epochForDataSequenceNumber(sequenceNumber);
    }

    private enum ServerState {
        NEW,
        WAITING_FOR_CLIENT_AUTH,
        CONNECTED,
        CLOSED
    }
}
