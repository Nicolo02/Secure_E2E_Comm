import java.io.DataInputStream;

import cipher.AESGCM_Cipher;

public class MessageReceiver extends Thread {

    private DataInputStream input;
    private AESGCM_Cipher cipher;

    public MessageReceiver(DataInputStream input, AESGCM_Cipher cipher) {
        this.input = input;
        this.cipher = cipher;
    }

    public void run() {
        try {
            while (true) {
                int length = input.readInt();
                if (length <= 0) {
                    System.out.println("Received empty message or connection closed.");
                    break;
                }

                // Read the encrypted message
                byte[] encryptedMessage = new byte[length];
                input.readFully(encryptedMessage);

                // Decrypt the message
                byte[] decryptedMessage = cipher.decrypt(encryptedMessage);

                // Convert bytes to string and print
                String message = new String(decryptedMessage);
                System.out.println("< OTHER > " + message);
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


