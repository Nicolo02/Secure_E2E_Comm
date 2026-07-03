package dh;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class DiffieHellman {

    /*
     * Using 2048 bits lenght to increase difficulty in computing
     * the discrete logarithm and compromise the shared secret 
     */
    public static final int KEY_SIZE = 2048; 
    
    /*
     * Generates a Diffie-Hellman key pair, to be used in the key exchange process.
     * Each client generate its own key pair, which will be used to compute the shared secret
     * with the other client.
     */
    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException{
        
        KeyPairGenerator keysGen = KeyPairGenerator.getInstance("DH");
        keysGen.initialize(KEY_SIZE);
        return keysGen.genKeyPair();
    }

    /*
     * Generetes the Shared Secret using it's own private key and the public key received from the other client.
     * The shared secret is computed using the Diffie-Hellman key agreement protocol.
     * The shared secret is the same for both clients, as long as they use the same DH parameters.
     */
    public static byte[] computeSharedSecret(PrivateKey privKey, PublicKey received_pubKey)throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyagr = KeyAgreement.getInstance("DH");
        keyagr.init(privKey);
        keyagr.doPhase(received_pubKey, true); // true because this is the last (and first, in this case) phase of the agreement
        return keyagr.generateSecret();
    }

    /*
     * Returns the encoded public key, which is used to send it to the other client by sockets
     */
    public static byte[] getEncodedPubKey(PublicKey pubKey) {
        if (pubKey == null) {
            return null;
        }
        return pubKey.getEncoded();
    }

    /*
     * Decodes the public key received from the other client, (encoded in X.509 format)
     * This is used to reconstruct the PublicKey object from the byte array received.
     */
    public static PublicKey decodePublicKey(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        return keyFactory.generatePublic(keySpec);
    }
}
