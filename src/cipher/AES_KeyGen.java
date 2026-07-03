package cipher;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES_KeyGen {

    /**
     * Derives a 128-bit AES key from the shared secret using SHA-256.
     * This method takes a byte array representing the shared secret,
     * computes its SHA-256 hash, and then extracts the first 128 bits (?)
     * @param sharedSecret The shared secret byte array.
     * @return A SecretKey object representing the derived AES key.
     */
    public static SecretKey deriveAESKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret); // output = 256 bit
        return new SecretKeySpec(keyBytes, 0, 16, "AES"); // taglia 128 bit
    }
}
