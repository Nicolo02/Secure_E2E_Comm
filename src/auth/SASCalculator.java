package auth;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/*
 * Calcola uno Short Authentication String (SAS): un codice numerico breve,
 * derivato dai nomi, dalle chiavi pubbliche DH e dal segreto condiviso di
 * entrambi i client, pensato per essere confrontato manualmente dagli utenti
 * (a voce, di persona, o tramite un altro canale) per rilevare un eventuale
 * Man-in-the-Middle nello scambio Diffie-Hellman.
 *
 * Principio: Diffie-Hellman, da solo, non può autenticare le parti. Se un
 * attaccante si inserisce nello scambio, stabilirà DUE segreti condivisi
 * distinti (uno con ciascun client) e quindi ciascun client calcolerà un SAS
 * diverso. Confrontando i due codici fuori banda, l'incoerenza tradisce
 * l'attacco.
 *
 * Il calcolo è simmetrico rispetto al ruolo (A o B): i due "record"
 * (nome + chiave pubblica) vengono ordinati canonicamente prima di essere
 * concatenati, cosicché entrambi i client - indipendentemente da chi ha
 * iniziato la connessione - ottengano esattamente lo stesso codice quando
 * non c'è un attaccante nel mezzo.
 */
public class SASCalculator {

    private static final int CODE_MODULO = 1_000_000; // codice a 6 cifre decimali

    private SASCalculator() {
        // utility class, non istanziabile
    }

    /*
     * Calcola il codice SAS a partire da nome e chiave pubblica DH (encoded,
     * X.509) di entrambi i client e dal segreto condiviso calcolato tramite
     * Diffie-Hellman.
     */
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

        // Primi 4 byte del digest -> intero positivo -> 6 cifre decimali
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