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
import com.kolich.security.sign.HmacSigner;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Worked example of {@link HmacSigner}, which signs with one shared secret rather than a key
 * pair. That makes it the right tool for checking an inbound webhook, or for an outbound
 * request signing scheme in the style of AWS Signature V2.
 *
 * <p>It is the wrong tool whenever the checking party must not be able to mint signatures of
 * its own, because with one secret it can; use {@link ByteSigner} with a key pair for that.
 */
public final class HmacSignerExampleTest {

    /**
     * In reality this comes from configuration or a secret manager, and the party on the
     * other end holds the identical value.
     */
    private static final String SHARED_SECRET = "s3cr3t-shared-with-the-other-side";

    /**
     * Verifying an inbound webhook, which is what this class gets used for most.
     */
    @Test
    public void verifiesAnInboundWebhook() {
        final String body = "{\"event\":\"upload.completed\",\"path\":\"/photos/nye.jpg\"}";

        // What the sender computed and put in a header, e.g. X-Signature.
        final String headerValue = new HmacSigner.Builder()
                .setSecret(SHARED_SECRET)
                .setMessage(body)
                .build()
                .sign();

        // Always check with verify(), never by comparing sign() yourself. verify() compares
        // through MessageDigest.isEqual, which does not return early on a differing byte;
        // String.equals does, and how long it took leaks how much of a forgery was right.
        final boolean trusted = new HmacSigner.Builder()
                .setSecret(SHARED_SECRET)
                .setMessage(body)
                .build()
                .verify(headerValue);

        assertTrue(trusted);
    }

    /**
     * A body that was edited in flight, or a sender using the wrong secret, both fail.
     */
    @Test
    public void rejectsTamperedBodyAndWrongSecret() {
        final String body = "{\"event\":\"upload.completed\",\"bytes\":1024}";

        final String headerValue = new HmacSigner.Builder()
                .setSecret(SHARED_SECRET)
                .setMessage(body)
                .build()
                .sign();

        // Same secret, body changed by one digit.
        assertFalse(new HmacSigner.Builder()
                .setSecret(SHARED_SECRET)
                .setMessage("{\"event\":\"upload.completed\",\"bytes\":1025}")
                .build()
                .verify(headerValue));

        // Same body, wrong secret.
        assertFalse(new HmacSigner.Builder()
                .setSecret("not-the-shared-secret")
                .setMessage(body)
                .build()
                .verify(headerValue));

        // A signature that is not even well-formed for the configured encoding is simply one
        // that does not match, so this is false rather than an exception.
        assertFalse(new HmacSigner.Builder()
                .setSecret(SHARED_SECRET)
                .setMessage(body)
                .build()
                .verify("%%% not base64 %%%"));
    }

    /**
     * Signing an outbound request, where the scheme dictates the wire format.
     */
    @Test
    public void choosesAlgorithmAndEncodingForTheWire() {
        final String stringToSign = "GET\n/api/v1/resources\nhost:onyx.koli.ch\n1790000000";

        // Hex is what a lot of webhook schemes expect. Base64 is the default here.
        final String hex = new HmacSigner.Builder()
                .setAlgorithm(HmacSigner.Algorithm.HMAC_SHA256)
                .setEncoding(HmacSigner.Encoding.HEX)
                .setSecret(SHARED_SECRET)
                .setMessage(stringToSign)
                .build()
                .sign();

        // HMAC-SHA256 is 32 bytes, so 64 hex characters.
        assertEquals(64, hex.length());

        // The encoding is presentation only - it does not change what was computed. But both
        // sides must agree on it, since verify() decodes using the configured encoding.
        final String base64 = new HmacSigner.Builder()
                .setEncoding(HmacSigner.Encoding.BASE64)
                .setSecret(SHARED_SECRET)
                .setMessage(stringToSign)
                .build()
                .sign();
        assertNotEquals(hex, base64);

        // Switching the digest does change the signature, and its length: 64 bytes for SHA-512.
        final byte[] sha512 = new HmacSigner.Builder()
                .setAlgorithm(HmacSigner.Algorithm.HMAC_SHA512)
                .setSecret(SHARED_SECRET)
                .setMessage(stringToSign)
                .build()
                .signToBytes();
        assertEquals(64, sha512.length);
    }

    /**
     * When the secret is random bytes from a key store rather than a passphrase, hand them
     * over directly instead of round-tripping through a string.
     */
    @Test
    public void takesRawSecretBytes() {
        final byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) i;
        }

        final byte[] tag = new HmacSigner.Builder()
                .setSecret(secret)
                .setMessage("signed with raw key bytes")
                .build()
                .signToBytes();

        // signToBytes() skips the encoding step entirely, which is what to use when the tag
        // is about to be embedded in a binary payload.
        assertEquals(32, tag.length);
        assertTrue(new HmacSigner.Builder()
                .setSecret(secret)
                .setMessage("signed with raw key bytes")
                .build()
                .verify(tag));
    }

}
