package protocol;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class Message {

    public static final int SEQ_NUMBER_SIZE = 8;

    private final long seqNumber;
    private final byte[] payload;

    public Message(long seqNumber, byte[] payload) {
        this.seqNumber = seqNumber;
        this.payload = payload;
    }

    public long getSeqNumber() {
        return seqNumber;
    }

    public byte[] getPayload() {
        return payload;
    }

    public String getPayloadAsString() {
        return new String(payload, StandardCharsets.UTF_8);
    }

    public byte[] seqNumberToAAD() {
        return ByteBuffer.allocate(SEQ_NUMBER_SIZE).putLong(seqNumber).array();
    }

    public static long aadToSeqNumber(byte[] aad) {
        if (aad == null || aad.length != SEQ_NUMBER_SIZE) {
            throw new IllegalArgumentException(
                "AAD non valido: lunghezza attesa " + SEQ_NUMBER_SIZE + " byte, ricevuti " +
                (aad == null ? "null" : aad.length));
        }
        return ByteBuffer.wrap(aad).getLong();
    }

    @Override
    public String toString() {
        return "Message{seq=" + seqNumber + ", payload=\"" + getPayloadAsString() + "\"}";
    }
}
