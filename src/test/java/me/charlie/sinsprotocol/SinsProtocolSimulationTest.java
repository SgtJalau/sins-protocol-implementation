package me.charlie.sinsprotocol;

import me.charlie.sinsprotocol.client.SinsClient;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.DataResponseMessage;
import me.charlie.sinsprotocol.protocol.message.EncryptedData;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.ProtocolConstants;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;
import me.charlie.sinsprotocol.protocol.validation.ProtocolException;
import me.charlie.sinsprotocol.server.SinsServer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SinsProtocolSimulationTest {

    /**
     * Confirms the normal protocol path.
     * The client and server complete HELLO, HELLO_ACK, CLIENT_AUTH and SERVER_AUTH, then exchange enough DATA_REQUEST/DATA_RESPONSE pairs to cross the first epoch boundary.
     */
    @Test
    void clientAndServerCompleteHandshakeAndExchangeEncryptedReadings() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(requestId -> "temperature=21." + requestId);

        completeHandshake(client, server);

        //We want to simulate at least one epoch change to confirm workings of epoch algorithm
        for (int index = 1; index <= 12; index++) {
            DataRequestMessage request = client.createDataRequest();
            DataResponseMessage response = server.handleDataRequest(request);

            assertEquals("temperature=21." + index, client.handleDataResponse(response));
        }

        //If nothing failed, client and server are still connected.
        assertTrue(client.isConnected());
        assertTrue(server.isConnected());
    }

    /**
     * Simulates sudden epoch mismatch.
     * A valid DATA_REQUEST is copied with a wrong epoch. The server must reject it before accepting the message because epoch controls which MAC and encryption keys are used.
     */
    @Test
    void serverRejectsSuddenEpochMismatch() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");
        completeHandshake(client, server);

        DataRequestMessage request = client.createDataRequest();
        DataRequestMessage wrongEpochRequest = new DataRequestMessage(
                request.epoch() + 1,
                request.messageMac(),
                request.sequenceNumber(),
                request.sessionId(),
                request.version()
        );

        assertThrows(ProtocolException.class, () -> server.handleDataRequest(wrongEpochRequest));
    }

    /**
     * Simulates protocol version downgrade or unsupported-version injection.
     * A valid DATA_REQUEST is copied with a different version.
     * The server must reject it because both endpoints have to agree on the same protocol rules.
     */
    @Test
    void serverRejectsVersionMismatch() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");
        completeHandshake(client, server);

        DataRequestMessage request = client.createDataRequest();
        DataRequestMessage wrongVersionRequest = new DataRequestMessage(
                request.epoch(),
                request.messageMac(),
                request.sequenceNumber(),
                request.sessionId(),
                ProtocolConstants.VERSION + 1
        );

        assertThrows(ProtocolException.class, () -> server.handleDataRequest(wrongVersionRequest));
    }

    /**
     * Simulates out-of-order message delivery.
     * A valid DATA_REQUEST is copied with a future sequence number.
     * The server must reject it because sequence numbers enforce strict ordering and prevent skipped or injected messages.
     */
    @Test
    void serverRejectsSequenceNumberMismatch() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");
        completeHandshake(client, server);

        DataRequestMessage request = client.createDataRequest();
        DataRequestMessage wrongSequenceRequest = new DataRequestMessage(
                request.epoch(),
                request.messageMac(),
                request.sequenceNumber() + 1,
                request.sessionId(),
                request.version()
        );

        assertThrows(ProtocolException.class, () -> server.handleDataRequest(wrongSequenceRequest));
    }

    /**
     * Simulates a replay attack.
     * The attacker reuses a valid DATA_REQUEST after it was already processed.
     * The server must reject the replay because the expected client sequence number has already moved forward.
     */
    @Test
    void serverRejectsReplayAttack() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");
        completeHandshake(client, server);

        DataRequestMessage request = client.createDataRequest();
        DataResponseMessage response = server.handleDataRequest(request);
        client.handleDataResponse(response);

        assertThrows(ProtocolException.class, () -> server.handleDataRequest(request));
    }

    /**
     * Simulates message tampering on protected fields.
     * The ciphertext of a valid DATA_RESPONSE is modified while the old MAC remains.
     * The client must reject it because HMAC-SHA256 covers the protected message fields before decryption is attempted.
     */
    @Test
    void clientRejectsTamperedDataResponseCiphertext() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "humidity=45");
        completeHandshake(client, server);

        DataRequestMessage request = client.createDataRequest();
        DataResponseMessage response = server.handleDataRequest(request);
        EncryptedData tamperedEncryptedData = new EncryptedData(
                response.encryptedData().ciphertext() + "A",
                response.encryptedData().nonce(),
                response.encryptedData().tag()
        );
        DataResponseMessage tamperedResponse = new DataResponseMessage(
                tamperedEncryptedData,
                response.epoch(),
                response.messageMac(),
                response.requestId(),
                response.sequenceNumber(),
                response.sessionId(),
                response.version()
        );

        assertThrows(ProtocolException.class, () -> client.handleDataResponse(tamperedResponse));
    }

    /**
     * Simulates passive eavesdropping.
     * The attacker can see the DATA_RESPONSE packet but only receives ciphertext, nonce and tag.
     * The plaintext reading is not present in the transmitted encrypted-data object.
     */
    @Test
    void eavesdropperOnlySeesCiphertextForDataResponsePayload() {
        SinsClient client = new SinsClient();
        String plaintextReading = "battery=87%";
        SinsServer server = new SinsServer(ignoredRequestId -> plaintextReading);
        completeHandshake(client, server);

        DataRequestMessage request = client.createDataRequest();
        DataResponseMessage response = server.handleDataRequest(request);

        assertNotEquals(plaintextReading, response.encryptedData().ciphertext());
        assertFalse(response.encryptedData().ciphertext().contains(plaintextReading));
        assertEquals(plaintextReading, client.handleDataResponse(response));
    }

    /**
     * Simulates client impersonation with the wrong pre-shared key.
     * A fake client can complete the public HELLO exchange, but it cannot create a valid CLIENT_AUTH message because the HMAC keys depend on SENSOR_PRE_SHARED_KEY.
     */
    @Test
    void serverRejectsClientImpersonationWithWrongPreSharedKey() {
        SinsClient fakeClient = new SinsClient("WrongClientPreSharedKey");
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");

        HelloMessage hello = fakeClient.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage fakeClientAuth = fakeClient.handleHelloAck(helloAck);

        assertThrows(ProtocolException.class, () -> server.handleClientAuth(fakeClientAuth));
    }

    /**
     * Simulates server impersonation by replacing the server proof.
     * The client receives a SERVER_AUTH-shaped message with the correct session and sequence number, but the proof value is not derived from the shared PSK and transcript.
     * The client must reject it.
     */
    @Test
    void clientRejectsServerImpersonationWithInvalidProof() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");

        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);
        ServerAuthMessage validServerAuth = server.handleClientAuth(clientAuth);
        ServerAuthMessage forgedServerAuth = new ServerAuthMessage(
                "forged-auth-value",
                validServerAuth.epoch(),
                validServerAuth.messageMac(),
                validServerAuth.sequenceNumber(),
                validServerAuth.sessionId(),
                validServerAuth.version()
        );

        assertThrows(ProtocolException.class, () -> client.handleServerAuth(forgedServerAuth));
    }

    /**
     * Simulates man-in-the-middle message modification during authentication.
     * A valid CLIENT_AUTH is intercepted and its auth-value is replaced.
     * The server must reject it because the MAC no longer matches the modified packet and the authentication proof is invalid.
     */
    @Test
    void serverRejectsManInTheMiddleModifiedClientAuth() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");

        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);
        ClientAuthMessage modifiedClientAuth = new ClientAuthMessage(
                "modified-auth-value",
                clientAuth.epoch(),
                clientAuth.messageMac(),
                clientAuth.sequenceNumber(),
                clientAuth.sessionId(),
                clientAuth.version()
        );

        assertThrows(ProtocolException.class, () -> server.handleClientAuth(modifiedClientAuth));
    }

    /**
     * Simulates session hijacking with only a stolen session id.
     * The attacker knows the session id and expected sequence number, but not the derived MAC key.
     * The forged DATA_REQUEST must be rejected because session id alone is not authentication.
     */
    @Test
    void serverRejectsSessionHijackingWithOnlySessionId() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(ignoredRequestId -> "temperature=21");
        completeHandshake(client, server);

        DataRequestMessage forgedRequest = new DataRequestMessage(
                0,
                "forged-message-mac",
                3,
                client.sessionId(),
                ProtocolConstants.VERSION
        );

        assertThrows(ProtocolException.class, () -> server.handleDataRequest(forgedRequest));
    }

    /**
     * Simulates handshake key mismatch.
     * The endpoints use different pre-shared keys.
     * Diffie-Hellman still creates a shared secret, but authentication fails because the derived MAC and finished keys no longer match.
     */
    @Test
    void handshakeFailsWhenPreSharedKeysDoNotMatch() {
        SinsClient client = new SinsClient("ClientOnlyPreSharedKey");
        SinsServer server = new SinsServer("ServerOnlyPreSharedKey", ignoredRequestId -> "temperature=21");

        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);

        assertThrows(ProtocolException.class, () -> server.handleClientAuth(clientAuth));
    }

    private void completeHandshake(SinsClient client, SinsServer server) {
        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);
        ServerAuthMessage serverAuth = server.handleClientAuth(clientAuth);
        client.handleServerAuth(serverAuth);
    }
}
