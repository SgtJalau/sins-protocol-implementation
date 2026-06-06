package me.charlie.sinsprotocol;

import me.charlie.sinsprotocol.client.SinsClient;
import me.charlie.sinsprotocol.protocol.message.ClientAuthMessage;
import me.charlie.sinsprotocol.protocol.message.DataRequestMessage;
import me.charlie.sinsprotocol.protocol.message.DataResponseMessage;
import me.charlie.sinsprotocol.protocol.message.EncryptedData;
import me.charlie.sinsprotocol.protocol.message.HelloAckMessage;
import me.charlie.sinsprotocol.protocol.message.HelloMessage;
import me.charlie.sinsprotocol.protocol.message.ServerAuthMessage;
import me.charlie.sinsprotocol.protocol.validation.ProtocolException;
import me.charlie.sinsprotocol.server.SinsServer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SinsProtocolSimulationTest {

    @Test
    void clientAndServerCompleteHandshakeAndExchangeEncryptedReadings() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(requestId -> "temperature=21." + requestId);

        completeHandshake(client, server);

        for (int index = 1; index <= 12; index++) {
            DataRequestMessage request = client.createDataRequest();
            DataResponseMessage response = server.handleDataRequest(request);

            assertEquals("temperature=21." + index, client.handleDataResponse(response));
        }

        assertTrue(client.isConnected());
        assertTrue(server.isConnected());
    }

    @Test
    void clientRejectsTamperedDataResponseCiphertext() {
        SinsClient client = new SinsClient();
        SinsServer server = new SinsServer(requestId -> "humidity=45");
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

    private void completeHandshake(SinsClient client, SinsServer server) {
        HelloMessage hello = client.startHandshake();
        HelloAckMessage helloAck = server.handleHello(hello);
        ClientAuthMessage clientAuth = client.handleHelloAck(helloAck);
        ServerAuthMessage serverAuth = server.handleClientAuth(clientAuth);
        client.handleServerAuth(serverAuth);
    }
}
