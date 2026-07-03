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

    public byte[] encrypt(byte[] plaintext) throws Exception{
        return encrypt(plaintext, null);
    }

    public byte[] encrypt(byte[] plaintext, byte[] aad) throws Exception{

        byte [] result;

        // Generates the IV
        byte [] iv = new byte[IV_SIZE];
        sr.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(MAC_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        // Encrypts the plaintext
        byte[] cipherText = cipher.doFinal(plaintext);

        // Return IV + ciphertext 
        result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

        return result;
    }

    public byte[] decrypt(byte[] input) throws Exception {
        return decrypt(input, null);
    }

    public byte[] decrypt(byte[] input, byte[] aad) throws Exception {

        // Extract the IV from the beginning of the input
        if (input.length < IV_SIZE) {
            throw new IllegalArgumentException("Ciphertext is too short to contain a valid IV.");
        }
        byte[] iv = Arrays.copyOfRange(input, 0, IV_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(input, IV_SIZE, input.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(MAC_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        return cipher.doFinal(ciphertext);

    }

}