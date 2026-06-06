package me.charlie.sinsprotocol.protocol.message;

//Central protocol values shared by message creation, validation and later crypto code.
public final class ProtocolConstants {

    public static final int VERSION = 1;
    public static final int FIRST_SEQUENCE_NUMBER = 1;
    public static final int FIRST_DATA_SEQUENCE_NUMBER = 3;
    public static final int EPOCH_MESSAGE_COUNT = 10;
    public static final String MESSAGE_MAC_FIELD = "msg-mac";

    private ProtocolConstants() {
    }

    //Converts DATA_REQUEST/DATA_RESPONSE sequence numbers to the key epoch used for MAC and encryption keys.
    public static int epochForDataSequenceNumber(long sequenceNumber) {
        if (sequenceNumber < FIRST_DATA_SEQUENCE_NUMBER) {
            throw new IllegalArgumentException("Data sequence number must be at least " + FIRST_DATA_SEQUENCE_NUMBER);
        }

        return Math.toIntExact((sequenceNumber - FIRST_DATA_SEQUENCE_NUMBER) / EPOCH_MESSAGE_COUNT);
    }
}
