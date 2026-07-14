package io.dalang.sso;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** A PKCE verifier/challenge pair (RFC 7636, S256). */
public final class Pkce {

    public final String verifier;
    public final String challenge;

    private Pkce(String verifier, String challenge) {
        this.verifier = verifier;
        this.challenge = challenge;
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    /** Generate a random verifier and derive its S256 challenge. */
    public static Pkce generate() {
        byte[] buf = new byte[32];
        RANDOM.nextBytes(buf);
        String verifier = B64URL.encodeToString(buf);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String challenge = B64URL.encodeToString(digest);
            return new Pkce(verifier, challenge);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present on every JVM.
            throw new IllegalStateException(e);
        }
    }
}
