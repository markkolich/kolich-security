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

package com.kolich.security.sign;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class StringSignerTest {

    private static final KeyPair KEY_PAIR = generateKeyPair();

    private static final KeyPair OTHER_KEY_PAIR = generateKeyPair();

    private static final StringSigner SIGNER = new StringSigner.Builder()
            .setPublicKey(KEY_PAIR.getPublic())
            .setPrivateKey(KEY_PAIR.getPrivate())
            .build();

    @ParameterizedTest
    @ValueSource(strings = {
        "hello world",
        "a",
        "",
        "{\"user\":\"mark\",\"roles\":[\"admin\"]}",
        "contains/slashes+and=padding?chars&too",
        "éèê unicode 你好 🚀 emoji",
        "   leading and trailing whitespace   ",
        "line\nbreak\tand\ttabs"
    })
    public void signThenVerifyAndGetRoundTrip(
            final String plaintext) {
        final String signed = SIGNER.sign(plaintext);

        assertTrue(SIGNER.verify(signed));
        assertEquals(plaintext, SIGNER.verifyAndGet(signed));
    }

    @ParameterizedTest
    @EnumSource(ByteSigner.Algorithm.class)
    public void roundTripsUnderEveryAlgorithm(
            final ByteSigner.Algorithm algorithm) {
        final StringSigner signer = new StringSigner.Builder()
                .setAlgorithm(algorithm)
                .setPublicKey(KEY_PAIR.getPublic())
                .setPrivateKey(KEY_PAIR.getPrivate())
                .build();

        final String signed = signer.sign("round trip");

        assertEquals("round trip", signer.verifyAndGet(signed));
    }

    /**
     * Locks in the on-the-wire payload format: URL-safe Base64 over a four byte big-endian
     * signature length, the signature, then the UTF-8 message. Changing any of that would
     * invalidate every token already issued by a deployed consumer, so it should not be
     * possible to do by accident.
     */
    @Test
    public void payloadFormatIsUrlSafeBase64OverALengthPrefixedSignature() {
        final String plaintext = "format check";

        final String signed = SIGNER.sign(plaintext);

        // URL-safe Base64 alphabet only: no '+' and no '/'.
        assertFalse(signed.contains("+"));
        assertFalse(signed.contains("/"));

        final byte[] decoded = Base64.getUrlDecoder().decode(signed);

        final int sigLength = ByteBuffer.wrap(decoded).getInt();
        assertEquals(256, sigLength); // 2048-bit RSA key

        final byte[] expectedMessage = plaintext.getBytes(StandardCharsets.UTF_8);
        assertEquals(Integer.BYTES + sigLength + expectedMessage.length, decoded.length);

        final String message = new String(decoded, Integer.BYTES + sigLength,
                expectedMessage.length, StandardCharsets.UTF_8);
        assertEquals(plaintext, message);
    }

    @Test
    public void tamperedPayloadDoesNotVerify() {
        final String signed = SIGNER.sign("the quick brown fox");

        // Flip the final character of the Base64 payload to something else in the alphabet.
        final char last = signed.charAt(signed.length() - 1);
        final String tampered = signed.substring(0, signed.length() - 1)
                + (last == 'A' ? 'B' : 'A');

        assertNotEquals(signed, tampered);
        assertFalse(SIGNER.verify(tampered));
        assertNull(SIGNER.verifyAndGet(tampered));
    }

    /**
     * Input that is not well-formed Base64 is an invalid token rather than an error, so it
     * comes back null rather than throwing.
     */
    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "!!!not base64!!!",
        "a",
        "////+++",
        "short",
        "%%%%",
        "AAAA"
    })
    public void malformedInputDoesNotVerify(
            final String malformed) {
        assertFalse(SIGNER.verify(malformed));
        assertNull(SIGNER.verifyAndGet(malformed));
    }

    @Test
    public void payloadSignedByAnotherKeyDoesNotVerify() {
        final StringSigner otherSigner = new StringSigner.Builder()
                .setPrivateKey(OTHER_KEY_PAIR.getPrivate())
                .build();

        final String signed = otherSigner.sign("signed by the wrong key");

        assertFalse(SIGNER.verify(signed));
        assertNull(SIGNER.verifyAndGet(signed));
    }

    @Test
    public void verifyOnlySignerCannotSign() {
        final StringSigner verifyOnly = new StringSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .build();

        assertEquals("ok", verifyOnly.verifyAndGet(SIGNER.sign("ok")));
        assertThrows(NullPointerException.class, () -> verifyOnly.sign("nope"));
    }

    @Test
    public void signOnlySignerCannotVerify() {
        final StringSigner signOnly = new StringSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .build();

        final String signed = signOnly.sign("ok");

        assertEquals("ok", SIGNER.verifyAndGet(signed));
        assertThrows(NullPointerException.class, () -> signOnly.verifyAndGet(signed));
    }

    @Test
    public void nullArgumentsThrow() {
        assertThrows(NullPointerException.class, () -> SIGNER.sign(null));
        assertThrows(NullPointerException.class, () -> SIGNER.verifyAndGet(null));
        assertThrows(NullPointerException.class, () -> SIGNER.verify(null));

        final StringSigner.Builder builder = new StringSigner.Builder();
        assertThrows(NullPointerException.class, () -> builder.setAlgorithm(null));
    }

    /**
     * Signing the same string twice yields the same payload, because RSA PKCS#1 v1.5
     * signatures are deterministic. This is asserted so that a future change to a
     * randomized scheme is a deliberate, visible decision rather than a surprise.
     */
    @Test
    public void signingIsDeterministic() {
        assertEquals(SIGNER.sign("same input"), SIGNER.sign("same input"));
    }

    private static KeyPair generateKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key pair generation is unavailable.", e);
        }
    }

}
