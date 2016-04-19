package aredev.thesis;

import org.irmacard.credentials.idemix.IdemixIssuer;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Abdullah Rasool on 12-4-16.
 */
public class Main {

    public static void main(String[] args) {
        thesisIssuer ti = new thesisIssuer();
        thesisVerifier tv = new thesisVerifier();
    }


}
