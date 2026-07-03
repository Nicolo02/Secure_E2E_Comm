package cipher;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AESGCM_Cipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12; // 96 bit

    // AES-GCM is an AEAD cipher and requires the user to input the length of the Message Authentication Code.
    private static final int MAC_LENGTH = 128;

    private final SecretKey key;
    private final SecureRandom sr;

    public AESGCM_Cipher(SecretKey key){
        this.key = key;
        this.sr = new SecureRandom();
    }

    /*
     * Encrypts the given plaintext using AES in GCM mode.
     * The method generates a random IV, initializes the cipher with the key and IV,
     * and returns the IV concatenated with the ciphertext in order to allow decryption later.
     */
    public byte[] encrypt(byte[] plaintext) throws Exception{

        byte [] result;

        // Generates the IV
        byte [] iv = new byte[IV_SIZE];
        sr.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(MAC_LENGTH, iv);
        cipher.init(cipher.ENCRYPT_MODE, key, spec);

        // Encrypts the plaintext
        byte[] cipherText = cipher.doFinal(plaintext);

        // Return IV + ciphertext 
        result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

        return result;
    }

    /*
     * Decrypts the given ciphertext using AES in GCM mode.
     * The method extracts the IV from the beginning of the ciphertext,
     * initializes the cipher with the key and IV, and returns the decrypted plaintext.
     * 
     * Note: The input should include the IV at the beginning, as produced by the encrypt method.
    */
    public byte[] decrypt(byte[] input) throws Exception {

        // Extract the IV from the beginning of the input
        if (input.length < IV_SIZE) {
            throw new IllegalArgumentException("Ciphertext is too short to contain a valid IV.");
        }
        byte[] iv = Arrays.copyOfRange(input, 0, IV_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(input, IV_SIZE, input.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(MAC_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);

    }

}
