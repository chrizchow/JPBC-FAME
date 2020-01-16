package hk.chriz;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;

public class Main {

    // Attribute:
    static String [] attrs = {"ONE", "TWO", "THREE", "FOUR", "FIVE"};
    // Message:
    static String message = "SUCI:00000000000000000000000000000000";

    public static void main(String[] args) throws Exception {

        FAME cpabe = new FAME();

        // Initialisation:
        Instant start_init = Instant.now();
        FAMEMasterKey msk = cpabe.setup();
        Instant end_init = Instant.now();
        System.out.println("~~~~ Setup Complete ~~~~");
        System.out.println("elapsed time:" + Duration.between(start_init, end_init) + "\n");

        // Private Key Extraction / Generation:
        Instant start_keygen = Instant.now();
        FAMESecretKey skey = cpabe.keygen(msk, attrs);
        Instant end_keygen = Instant.now();
        System.out.println("~~~~ Keygen Complete ~~~~");
        System.out.println("elapsed time: " + Duration.between(start_keygen, end_keygen) + "\n");

        // Encryption:
        Instant start_enc = Instant.now();
        FAMECipherText cpt = cpabe.encrypt("ONE and TWO and THREE and FOUR and FIVE", message.getBytes());
        Instant end_enc = Instant.now();
        System.out.println("~~~~ Encryption Complete ~~~~");
        System.out.println("elapsed time: " + Duration.between(start_enc, end_enc) + "\n");

        // Decryption:
        Instant start_dec = Instant.now();
        byte[] decrypted = cpabe.decrypt(skey, cpt);
        Instant end_dec = Instant.now();
        System.out.println("~~~~ Decryption Complete ~~~~");
        System.out.println("elapsed time: " + Duration.between(start_dec, end_dec) + "\n");

        // Verification of decryption:
        String dec_message = new String(decrypted);
        if (dec_message.equals(message)) {
            System.out.println("~~~ Verification of Decryption Success ~~~ ");
        } else {
            System.err.println("=== Error: Decrypted text is not the same! ===");
            System.err.println("Original:"+message);
            System.err.println("Decrypted:"+dec_message);
        }

    }
}
