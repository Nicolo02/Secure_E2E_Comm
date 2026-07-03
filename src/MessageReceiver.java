import java.io.DataInputStream;
import java.util.Arrays;

import cipher.AESGCM_Cipher;
import protocol.Message;
import protocol.AntiReplay;

public class MessageReceiver extends Thread {

    private DataInputStream input;
    private AESGCM_Cipher cipher;
    private AntiReplay replayGuard;

    public MessageReceiver(DataInputStream input, AESGCM_Cipher cipher) {
        this.input = input;
        this.cipher = cipher;
        this.replayGuard = new AntiReplay();
    }

    public void run() {
        try {
            while (true) {
                int length = input.readInt();
                if (length <= 0) {
                    System.out.println("Received empty message or connection closed.");
                    break;
                }

                // Read the whole packet: [ AAD (seq, cleartext) | IV + ciphertext+tag ]
                byte[] packet = new byte[length];
                input.readFully(packet);

                if (length <= Message.SEQ_NUMBER_SIZE) {
                    System.err.println("Discarded malformed packet (too short to contain a sequence number).");
                    continue;
                }

                byte[] aad = Arrays.copyOfRange(packet, 0, Message.SEQ_NUMBER_SIZE);
                byte[] encryptedPayload = Arrays.copyOfRange(packet, Message.SEQ_NUMBER_SIZE, packet.length);

                long seqNumber;
                try {
                    seqNumber = Message.aadToSeqNumber(aad);
                } catch (IllegalArgumentException iae) {
                    System.err.println("Discarded malformed packet: " + iae.getMessage());
                    continue;
                }

                // Controllo anti-replay: scarta il messaggio se la sequenza non è
                // strettamente successiva all'ultima accettata, PRIMA di decifrare.
                if (!replayGuard.isValid(seqNumber)) {
                    System.err.println("Discarded message with sequence number " + seqNumber +
                        " (replay, duplicate or out-of-order - last accepted was " +
                        replayGuard.getLastAcceptedSeq() + ").");
                    continue;
                }

                // Decrypt the message, verifying that the sequence number (AAD) wasn't tampered with
                byte[] decryptedPayload;
                try {
                    decryptedPayload = cipher.decrypt(encryptedPayload, aad);
                } catch (Exception decryptionException) {
                    // Tag di autenticazione non valido: il messaggio (o il suo AAD) è stato
                    // manomesso. Lo scartiamo senza terminare il thread di ricezione.
                    System.err.println("Discarded message with sequence number " + seqNumber +
                        ": authentication failed (" + decryptionException.getMessage() + ").");
                    continue;
                }

                Message inMessage = new Message(seqNumber, decryptedPayload);
                System.out.println("< OTHER > " + inMessage.getPayloadAsString());
            }
        } catch (Exception e) {
            System.err.println("Error in MessageReceiver: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                input.close();
            } catch (Exception e) {
                System.err.println("Error closing input stream: " + e.getMessage());
            }
        }
    }
}