/*
 * Copyright (c) 2026 Mark S. Kolich
 * https://mark.koli.ch
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package com.kolich.security.examples;

import com.kolich.security.sign.ByteSigner;
import com.kolich.security.sign.StringSigner;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Worked example of {@link StringSigner}, the class to reach for when a string has to travel
 * through somewhere untrustworthy and come back unchanged: a session cookie, a query
 * parameter, an API key.
 *
 * <p>Signing conceals nothing. The payload carries the original string in the clear and
 * anyone can read it; what the signature proves is that nobody <em>changed</em> it. When the
 * contents themselves must be unreadable, encrypt instead.
 *
 * <p>Every method in this package is a real test, so none of these examples can quietly stop
 * being true.
 */
public final class StringSignerExampleTest {

    private static final KeyPair KEY_PAIR = generateKeyPair();
    private static final KeyPair ATTACKER_KEY_PAIR = generateKeyPair();

    /**
     * What a configuration file would actually hold: each half of the pair as Base64 text.
     * The public key is X.509, the private key PKCS#8 — which is what {@code openssl
     * genpkey} and {@code openssl rsa -pubout} write.
     */
    private static final String PUBLIC_KEY_CONFIG_VALUE =
            Base64.getEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded());
    private static final String PRIVATE_KEY_CONFIG_VALUE =
            Base64.getEncoder().encodeToString(KEY_PAIR.getPrivate().getEncoded());

    /**
     * Build the signer once and reuse it forever. Unlike {@link ByteSigner}, it holds keys
     * rather than a message, so it is immutable and thread safe — exactly the shape of thing
     * to keep in a singleton component rather than rebuild per request.
     */
    private static final StringSigner SIGNER = new StringSigner.Builder()
            .setPublicKey(PUBLIC_KEY_CONFIG_VALUE)
            .setPrivateKey(PRIVATE_KEY_CONFIG_VALUE)
            .build();

    /**
     * The round trip: sign on the way out, verify and recover on the way back in.
     */
    @Test
    public void signsAndVerifiesSessionCookie() {
        final String sessionPayload = "{\"user\":\"mark\",\"expires\":1790000000}";

        // On the way out. The result is URL-safe Base64, so it can go straight into a cookie
        // value or a query parameter with no further escaping.
        final String cookieValue = SIGNER.sign(sessionPayload);

        // On the way back in. verifyAndGet returns the original string, or null - there is no
        // state in which it hands back a payload it could not verify.
        final String recovered = SIGNER.verifyAndGet(cookieValue);
        assertEquals(sessionPayload, recovered);

        // verify() is the same check for when the message itself is not needed.
        assertTrue(SIGNER.verify(cookieValue));

        // Proof that this is a signature and not encryption: the message is right there.
        final byte[] decoded = Base64.getUrlDecoder().decode(cookieValue);
        assertTrue(new String(decoded, StandardCharsets.UTF_8).endsWith(sessionPayload));
    }

    /**
     * Anything the holder of the cookie edits stops verifying, which is the entire point.
     */
    @Test
    public void rejectsTamperedCookie() {
        final String cookieValue = SIGNER.sign("{\"user\":\"mark\",\"admin\":false}");

        // Flip one character of the Base64. Any edit at all will do.
        final char swap = cookieValue.charAt(10) == 'A' ? 'B' : 'A';
        final String tampered = cookieValue.substring(0, 10) + swap + cookieValue.substring(11);

        assertFalse(SIGNER.verify(tampered));
        assertNull(SIGNER.verifyAndGet(tampered));

        // Garbage that is not even Base64 is just an invalid payload, not an exception.
        assertNull(SIGNER.verifyAndGet("!!! definitely not a cookie !!!"));
    }

    /**
     * The reason to use a key pair rather than a shared secret: a service can be given the
     * ability to check tokens without the ability to mint them.
     */
    @Test
    public void verifierHoldsOnlyThePublicKey() {
        final StringSigner verifyOnly = new StringSigner.Builder()
                .setPublicKey(PUBLIC_KEY_CONFIG_VALUE)
                .build();

        final String cookieValue = SIGNER.sign("issued by the service that holds the private key");

        // It can verify.
        assertEquals("issued by the service that holds the private key",
                verifyOnly.verifyAndGet(cookieValue));

        // It cannot sign. Signing without a private key is a programming error, so unlike an
        // invalid payload it throws rather than returning null.
        assertThrows(NullPointerException.class, () -> verifyOnly.sign("forged"));

        // And a token from a different key pair does not verify here.
        final StringSigner attacker = new StringSigner.Builder()
                .setPrivateKey(ATTACKER_KEY_PAIR.getPrivate())
                .build();
        assertNull(verifyOnly.verifyAndGet(attacker.sign("minted with the wrong key")));
    }

    /**
     * Both sides have to agree on the algorithm; it is not recorded in the payload.
     */
    @Test
    public void choosesTheSignatureAlgorithm() {
        final StringSigner sha256 = new StringSigner.Builder()
                .setAlgorithm(ByteSigner.Algorithm.SHA256_WITH_RSA)
                .setPublicKey(KEY_PAIR.getPublic())
                .setPrivateKey(KEY_PAIR.getPrivate())
                .build();

        final String signed = sha256.sign("signed under SHA-256");
        assertEquals("signed under SHA-256", sha256.verifyAndGet(signed));

        // SIGNER is on the default, SHA512withRSA, so it cannot read what SHA-256 wrote.
        assertNull(SIGNER.verifyAndGet(signed));
    }

    private static KeyPair generateKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is required to be available.", e);
        }
    }

}
