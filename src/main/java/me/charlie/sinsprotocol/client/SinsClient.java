package me.charlie.sinsprotocol.client;

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
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolConstants;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;
import me.charlie.sinsprotocol.protocol.exception.ProtocolException;
import me.charlie.sinsprotocol.util.ProtocolPacketLogger;

import java.security.KeyPair;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Queue;
import java.util.logging.Logger;

public final class SinsClient {

    public static final String SENSOR_PRE_SHARED_KEY = "SensorClientServerPreSharedKey2026!";

    private static final Logger LOGGER = Logger.getLogger(SinsClient.class.getName());

    private final byte[] preSharedKey;
    private final Queue<Long> outstandingRequestIds = new ArrayDeque<>();
    private final ProtocolPacketLogger packetLogger;

    private KeyPair keyPair;
    private HelloMessage helloMessage;
    private HelloAckMessage helloAckMessage;
    private ClientAuthMessage clientAuthMessage;
    private SessionKeys sessionKeys;

    private ClientState state = ClientState.NEW;
    private long nextClientSequenceNumber = 1;
    private long nextServerSequenceNumber = 1;
    private String sessionId;

    public SinsClient() {
        this(SENSOR_PRE_SHARED_KEY, false);
    }

    public SinsClient(boolean showcaseLoggingEnabled) {
        this(SENSOR_PRE_SHARED_KEY, showcaseLoggingEnabled);
    }

    public SinsClient(String preSharedKey) {
        this(preSharedKey, false);
    }

    /**
     * Creates a client session. Showcase logging prints protocol packets for demos, but does not change protocol behavior.
     */
    public SinsClient(String preSharedKey, boolean showcaseLoggingEnabled) {
        this.preSharedKey = ProtocolEncoding.utf8(Objects.requireNonNull(preSharedKey, "preSharedKey"));
        this.packetLogger = new ProtocolPacketLogger("CLIENT", showcaseLoggingEnabled, LOGGER);
    }

    /**
     * Enables or disables packet logging for demo output.
     */
    public void setShowcaseLoggingEnabled(boolean showcaseLoggingEnabled) {
        packetLogger.setEnabled(showcaseLoggingEnabled);
    }

    public boolean isShowcaseLoggingEnabled() {
        return packetLogger.isEnabled();
    }

    /**
     * Controls whether logged packet JSON is compact or formatted across multiple lines.
     */
    public void setPrettyPrintPacketLogs(boolean prettyPrintPacketLogs) {
        packetLogger.setPrettyPrintJson(prettyPrintPacketLogs);
    }

    /**
     * Controls whether logged packet JSON is wrapped in ANSI color codes.
     */
    public void setColorizePacketLogs(boolean colorizePacketLogs) {
        packetLogger.setColorizeJson(colorizePacketLogs);
    }

    /**
     * Starts the client side of the handshake with a fresh session id, nonce and X25519 key pair.
     */
    public HelloMessage startHandshake() {
        requireState(ClientState.NEW);
        keyPair = X25519KeyExchange.generateKeyPair();
        sessionId = ProtocolEncoding.randomBase64Url(16);
        helloMessage = new HelloMessage(
                X25519KeyExchange.encodePublicKey(keyPair.getPublic()),
                ProtocolEncoding.randomBase64Url(32),
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        nextClientSequenceNumber++;
        state = ClientState.WAITING_FOR_HELLO_ACK;
        packetLogger.outgoing(helloMessage);
        return helloMessage;
    }

    /**
     * Verifies HELLO_ACK, derives session keys and returns CLIENT_AUTH as the client proof.
     */
    public ClientAuthMessage handleHelloAck(HelloAckMessage receivedHelloAckMessage) {
        packetLogger.incoming(receivedHelloAckMessage);
        requireState(ClientState.WAITING_FOR_HELLO_ACK);
        validateSession(receivedHelloAckMessage.sessionId(), receivedHelloAckMessage.version());
        validateSequence(receivedHelloAckMessage.sequenceNumber(), nextServerSequenceNumber, "server");

        helloAckMessage = receivedHelloAckMessage;
        nextServerSequenceNumber++;
        byte[] sharedSecret = X25519KeyExchange.sharedSecret(keyPair, receivedHelloAckMessage.serverKeyShare());
        byte[] transcriptHash = TranscriptHash.initial(helloMessage, receivedHelloAckMessage);
        sessionKeys = SessionKeys.derive(preSharedKey, sharedSecret, transcriptHash);

        String authValue = MessageAuthentication.hmacBase64Url(sessionKeys.clientFinishedKey(), transcriptHash);
        ClientAuthMessage unsignedClientAuthMessage = new ClientAuthMessage(
                authValue,
                0,
                "",
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        String messageMac = MessageAuthentication.messageMac(sessionKeys.epoch(0).clientMacKey(), unsignedClientAuthMessage);
        clientAuthMessage = new ClientAuthMessage(
                authValue,
                0,
                messageMac,
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        nextClientSequenceNumber++;
        state = ClientState.WAITING_FOR_SERVER_AUTH;
        packetLogger.outgoing(clientAuthMessage);
        return clientAuthMessage;
    }

    /**
     * Completes mutual authentication after validating SERVER_AUTH MAC and server proof.
     */
    public void handleServerAuth(ServerAuthMessage serverAuthMessage) {
        packetLogger.incoming(serverAuthMessage);
        requireState(ClientState.WAITING_FOR_SERVER_AUTH);
        validateSession(serverAuthMessage.sessionId(), serverAuthMessage.version());
        validateSequence(serverAuthMessage.sequenceNumber(), nextServerSequenceNumber, "server");
        validateEpoch(serverAuthMessage.epoch(), 0);

        EpochKeys epochKeys = sessionKeys.epoch(0);
        MessageAuthentication.verifyMessageMac(epochKeys.serverMacKey(), serverAuthMessage, serverAuthMessage.messageMac());
        byte[] transcriptHash = TranscriptHash.withClientAuth(helloMessage, helloAckMessage, clientAuthMessage);
        MessageAuthentication.verifyAuthenticationValue(
                sessionKeys.serverFinishedKey(),
                transcriptHash,
                serverAuthMessage.authValue()
        );

        nextServerSequenceNumber++;
        state = ClientState.CONNECTED;
    }

    /**
     * Accepts an authenticated server-side close packet and marks the client session closed.
     */
    public void handleServerClose(CloseMessage closeMessage) {
        packetLogger.incoming(closeMessage);
        validateSession(closeMessage.sessionId(), closeMessage.version());
        validateSequence(closeMessage.sequenceNumber(), nextServerSequenceNumber, "server");
        int expectedEpoch = closeEpoch(closeMessage.sequenceNumber());
        validateEpoch(closeMessage.epoch(), expectedEpoch);
        MessageAuthentication.verifyMessageMac(
                sessionKeys.epoch(closeMessage.epoch()).serverMacKey(),
                closeMessage,
                closeMessage.messageMac()
        );
        nextServerSequenceNumber++;
        state = ClientState.CLOSED;
    }

    /**
     * Creates an authenticated DATA_REQUEST for the next expected sensor reading.
     */
    public DataRequestMessage createDataRequest() {
        requireState(ClientState.CONNECTED);
        int epoch = ProtocolConstants.epochForDataSequenceNumber(nextClientSequenceNumber);
        DataRequestMessage unsignedMessage = new DataRequestMessage(
                epoch,
                "",
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        String messageMac = MessageAuthentication.messageMac(sessionKeys.epoch(epoch).clientMacKey(), unsignedMessage);
        DataRequestMessage dataRequestMessage = new DataRequestMessage(
                epoch,
                messageMac,
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        outstandingRequestIds.add(requestIdFor(dataRequestMessage.sequenceNumber()));
        nextClientSequenceNumber++;
        packetLogger.outgoing(dataRequestMessage);
        return dataRequestMessage;
    }

    /**
     * Verifies DATA_RESPONSE metadata and MAC first, then decrypts and returns the sensor reading.
     */
    public String handleDataResponse(DataResponseMessage dataResponseMessage) {
        packetLogger.incoming(dataResponseMessage);
        requireState(ClientState.CONNECTED);
        validateSession(dataResponseMessage.sessionId(), dataResponseMessage.version());
        validateSequence(dataResponseMessage.sequenceNumber(), nextServerSequenceNumber, "server");
        int expectedEpoch = ProtocolConstants.epochForDataSequenceNumber(dataResponseMessage.sequenceNumber());
        validateEpoch(dataResponseMessage.epoch(), expectedEpoch);
        validateOutstandingRequest(dataResponseMessage.requestId());

        EpochKeys epochKeys = sessionKeys.epoch(dataResponseMessage.epoch());
        MessageAuthentication.verifyMessageMac(epochKeys.serverMacKey(), dataResponseMessage, dataResponseMessage.messageMac());
        String plaintext = DataResponseCipher.decrypt(
                epochKeys.serverEncryptionKey(),
                dataResponseMessage.epoch(),
                dataResponseMessage.requestId(),
                dataResponseMessage.sequenceNumber(),
                dataResponseMessage.sessionId(),
                dataResponseMessage.version(),
                dataResponseMessage.encryptedData()
        );

        outstandingRequestIds.remove();
        nextServerSequenceNumber++;
        return plaintext;
    }

    /**
     * Creates an authenticated CLOSE packet from the current client sequence number.
     */
    public CloseMessage createClose(CloseReason closeReason) {
        requireConnectedOrHandshake();
        int epoch = closeEpoch(nextClientSequenceNumber);
        CloseMessage unsignedCloseMessage = new CloseMessage(
                epoch,
                "",
                closeReason,
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        String messageMac = MessageAuthentication.messageMac(sessionKeys.epoch(epoch).clientMacKey(), unsignedCloseMessage);
        CloseMessage closeMessage = new CloseMessage(
                epoch,
                messageMac,
                closeReason,
                nextClientSequenceNumber,
                sessionId,
                ProtocolConstants.VERSION
        );
        nextClientSequenceNumber++;
        state = ClientState.CLOSED;
        packetLogger.outgoing(closeMessage);
        return closeMessage;
    }

    public boolean isConnected() {
        return state == ClientState.CONNECTED;
    }

    public String sessionId() {
        return sessionId;
    }

    private void validateOutstandingRequest(long requestId) {
        Long expectedRequestId = outstandingRequestIds.peek();
        if (expectedRequestId == null || expectedRequestId != requestId) {
            throw new ProtocolException("DATA_RESPONSE does not match an outstanding DATA_REQUEST");
        }
    }

    //Session id, version, sequence number and epoch are checked separately so protocol errors are easier to diagnose.
    private void validateSession(String receivedSessionId, int version) {
        if (!Objects.equals(sessionId, receivedSessionId)) {
            throw new ProtocolException("Session id does not match");
        }
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

    private void requireState(ClientState expectedState) {
        if (state != expectedState) {
            throw new ProtocolException("Client is in state " + state + " but expected " + expectedState);
        }
    }

    private void requireConnectedOrHandshake() {
        if (state != ClientState.CONNECTED && state != ClientState.WAITING_FOR_SERVER_AUTH) {
            throw new ProtocolException("Client cannot close from state " + state);
        }
    }

    private long requestIdFor(long sequenceNumber) {
        return sequenceNumber - 2;
    }

    //CLOSE can happen before data exchange, so early close packets still use epoch 0.
    private int closeEpoch(long sequenceNumber) {
        if (sequenceNumber < ProtocolConstants.FIRST_DATA_SEQUENCE_NUMBER) {
            return 0;
        }
        return ProtocolConstants.epochForDataSequenceNumber(sequenceNumber);
    }

    private enum ClientState {
        NEW,
        WAITING_FOR_HELLO_ACK,
        WAITING_FOR_SERVER_AUTH,
        CONNECTED,
        CLOSED
    }
}
