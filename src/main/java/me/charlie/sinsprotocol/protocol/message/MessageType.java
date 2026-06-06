package me.charlie.sinsprotocol.protocol.message;

//Wire-level packet types used in the msg-type field.
public enum MessageType {
    HELLO,
    HELLO_ACK,
    CLIENT_AUTH,
    SERVER_AUTH,
    DATA_REQUEST,
    DATA_RESPONSE,
    CLOSE
}
