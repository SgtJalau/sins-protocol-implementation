package me.charlie.sinsprotocol.protocol.message;

//Protocol messages protected by an epoch-specific msg-mac. HELLO and HELLO_ACK are authenticated by transcript binding instead.
public sealed interface AuthenticatedProtocolMessage extends ProtocolMessage permits
        ClientAuthMessage,
        ServerAuthMessage,
        DataRequestMessage,
        DataResponseMessage,
        CloseMessage {

    int epoch();

    String messageMac();
}
