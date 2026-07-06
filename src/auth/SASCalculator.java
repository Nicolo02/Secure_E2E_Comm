package auth;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/*
 This class computes a Short Authentication String (SAS): a short numeric code derived from the names, 
 DH public keys and shared secret of both clients, intended to be manually compared by the users (by voice, in person, or through another channel)
 to detect a potential Man-in-the-Middle in the Diffie-Hellman exchange.

 If an attacker intercepts the DH exchange, they will establish two distinct shared secrets (one with each client),
 leading to different SAS codes.
*/

public class SASCalculator {

    private static final int CODE_MODULO = 1_000_000;

    private SASCalculator() {
        // utility class
    }

    public static String computeSAS(String nameA, byte[] pubKeyA,
                                     String nameB, byte[] pubKeyB,
                                     byte[] sharedSecret) throws IOException, NoSuchAlgorithmException {

        byte[] recordA = encodeRecord(nameA, pubKeyA);
        byte[] recordB = encodeRecord(nameB, pubKeyB);

        // Ordinamento canonico: indipendente da chi è "A" e chi è "B"
        byte[] first, second;
        if (Arrays.compare(recordA, recordB) <= 0) {
            first = recordA;
            second = recordB;
        } else {
            first = recordB;
            second = recordA;
        }

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(first);
        sha256.update(second);
        sha256.update(sharedSecret);
        byte[] digest = sha256.digest();

        // First 4 bytes of the digest -> positive integer -> 6 decimal digits
        int code = ((digest[0] & 0xFF) << 24) | ((digest[1] & 0xFF) << 16) |
                   ((digest[2] & 0xFF) << 8) | (digest[3] & 0xFF);
        code = Math.abs(code) % CODE_MODULO;

        return String.format("%06d", code);
    }

    private static byte[] encodeRecord(String name, byte[] pubKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeUTF(name);
        dos.write(pubKey);
        dos.flush();
        return baos.toByteArray();
    }
}