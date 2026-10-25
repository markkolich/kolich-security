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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class HmacSignerTest {

    private static final String SECRET = "a shared secret";

    private static final String MESSAGE = "GET\nTue, 25 Oct 2026 00:00:00 GMT\n\n/api/v1/thing";

    /**
     * Known-answer tests from RFC 2202 (HMAC-SHA1) and RFC 4231 (HMAC-SHA256 and
     * HMAC-SHA512). These check the output against the published vectors rather than merely
     * against itself, so a mistake in how the secret or message is fed to the MAC cannot
     * pass by being made consistently.
     *
     * <p>Test case 1 uses a key of twenty {@code 0x0b} bytes over {@code "Hi There"}; test
     * case 2 uses the key {@code "Jefe"} over {@code "what do ya want for nothing?"}.
     */
    @ParameterizedTest
    @CsvSource({
        "HMAC_SHA1,   1, b617318655057264e28bc0b6fb378c8ef146be00",
        "HMAC_SHA256, 1, b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "HMAC_SHA512, 1, 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d"
                + "6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        "HMAC_SHA1,   2, effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        "HMAC_SHA256, 2, 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "HMAC_SHA512, 2, 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea25055497"
                + "58bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    })
    public void matchesThePublishedRfcTestVectors(
            final HmacSigner.Algorithm algorithm,
            final int testCase,
            final String expectedHex) {
        final HmacSigner.Builder builder = new HmacSigner.Builder()
                .setAlgorithm(algorithm)
                .setEncoding(HmacSigner.Encoding.HEX);

        if (testCase == 1) {
            final byte[] key = new byte[20];
            Arrays.fill(key, (byte) 0x0b);
            builder.setSecret(key).setMessage("Hi There");
        } else {
            builder.setSecret("Jefe").setMessage("what do ya want for nothing?");
        }

        final HmacSigner signer = builder.build();

        assertEquals(expectedHex, signer.sign());
        assertTrue(signer.verify(expectedHex));
    }

    @ParameterizedTest
    @EnumSource(HmacSigner.Algorithm.class)
    public void signingIsDeterministicAndVerifies(
            final HmacSigner.Algorithm algorithm) {
        final String first = signer(algorithm, HmacSigner.Encoding.BASE64).sign();
        final String second = signer(algorithm, HmacSigner.Encoding.BASE64).sign();

        assertEquals(first, second);
        assertTrue(signer(algorithm, HmacSigner.Encoding.BASE64).verify(first));
    }

    @ParameterizedTest
    @CsvSource({
        "HMAC_SHA1,   20",
        "HMAC_SHA256, 32",
        "HMAC_SHA512, 64"
    })
    public void theRawSignatureLengthMatchesTheDigest(
            final HmacSigner.Algorithm algorithm,
            final int expectedLength) {
        assertEquals(expectedLength,
                signer(algorithm, HmacSigner.Encoding.HEX).signToBytes().length);
    }

    /**
     * The three encodings must be three renderings of the same bytes, not three different
     * signatures.
     */
    @Test
    public void everyEncodingRendersTheSameSignature() {
        final byte[] raw = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.HEX).signToBytes();

        final String base64 = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.BASE64).sign();
        final String base64Url = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.BASE64_URL).sign();
        final String hex = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.HEX).sign();

        assertArrayEquals(raw, Base64.getDecoder().decode(base64));
        assertArrayEquals(raw, Base64.getUrlDecoder().decode(base64Url));
        assertEquals(raw.length * 2, hex.length());

        // Hex output is lowercase.
        assertEquals(hex.toLowerCase(Locale.US), hex);
    }

    @Test
    public void theUrlSafeEncodingAvoidsThePlusAndSlashCharacters() {
        // A 64-byte SHA-512 MAC Base64s to 88 characters, which in practice always contains
        // at least one '+' or '/' for one of these two messages.
        final String standard = new HmacSigner.Builder()
                .setAlgorithm(HmacSigner.Algorithm.HMAC_SHA512)
                .setEncoding(HmacSigner.Encoding.BASE64)
                .setSecret(SECRET)
                .setMessage("find me a plus or a slash")
                .build()
                .sign();
        final String urlSafe = new HmacSigner.Builder()
                .setAlgorithm(HmacSigner.Algorithm.HMAC_SHA512)
                .setEncoding(HmacSigner.Encoding.BASE64_URL)
                .setSecret(SECRET)
                .setMessage("find me a plus or a slash")
                .build()
                .sign();

        assertFalse(urlSafe.contains("+"));
        assertFalse(urlSafe.contains("/"));
        assertArrayEquals(Base64.getDecoder().decode(standard),
                Base64.getUrlDecoder().decode(urlSafe));
    }

    @ParameterizedTest
    @EnumSource(HmacSigner.Encoding.class)
    public void signatureOverADifferentMessageDoesNotVerify(
            final HmacSigner.Encoding encoding) {
        final String signature = new HmacSigner.Builder()
                .setEncoding(encoding)
                .setSecret(SECRET)
                .setMessage(MESSAGE)
                .build()
                .sign();

        final HmacSigner other = new HmacSigner.Builder()
                .setEncoding(encoding)
                .setSecret(SECRET)
                .setMessage(MESSAGE + "!")
                .build();

        assertNotEquals(signature, other.sign());
        assertFalse(other.verify(signature));
    }

    @ParameterizedTest
    @EnumSource(HmacSigner.Encoding.class)
    public void signatureUnderADifferentSecretDoesNotVerify(
            final HmacSigner.Encoding encoding) {
        final String signature = new HmacSigner.Builder()
                .setEncoding(encoding)
                .setSecret(SECRET)
                .setMessage(MESSAGE)
                .build()
                .sign();

        final HmacSigner other = new HmacSigner.Builder()
                .setEncoding(encoding)
                .setSecret("a different secret")
                .setMessage(MESSAGE)
                .build();

        assertFalse(other.verify(signature));
    }

    /**
     * A signature that is not well-formed for the configured encoding must come back as
     * simply not matching, rather than throwing out of a verification path.
     */
    @ParameterizedTest
    @CsvSource({
        "BASE64,     '!!! not base64 !!!'",
        "BASE64,     'short'",
        "BASE64,     ''",
        "BASE64_URL, '++//'",
        "BASE64_URL, '%%%%'",
        "HEX,        'nothex'",
        "HEX,        'abc'",
        "HEX,        ''",
        "HEX,        'zz'"
    })
    public void malformedExpectedSignatureDoesNotVerify(
            final HmacSigner.Encoding encoding,
            final String malformed) {
        assertFalse(signer(HmacSigner.Algorithm.HMAC_SHA256, encoding).verify(malformed));
    }

    @Test
    public void hexVerificationAcceptsEitherCase() {
        final HmacSigner signer = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.HEX);

        final String lower = signer.sign();
        final String upper = lower.toUpperCase(Locale.US);

        assertNotEquals(lower, upper);
        assertTrue(signer.verify(lower));
        assertTrue(signer.verify(upper));
    }

    @Test
    public void verifyingRawBytesWorksToo() {
        final HmacSigner signer = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.HEX);

        final byte[] raw = signer.signToBytes();

        assertTrue(signer.verify(raw));

        final byte[] tampered = raw.clone();
        tampered[0] ^= 0x01;
        assertFalse(signer.verify(tampered));

        // A correct prefix of the right signature must not pass either.
        assertFalse(signer.verify(Arrays.copyOf(raw, raw.length - 1)));
        assertFalse(signer.verify(new byte[0]));
    }

    /**
     * Every byte of the signature has to matter, including the last one, which is the byte a
     * short-circuiting comparison would be most likely to skip.
     */
    @Test
    public void everyByteOfTheSignatureIsChecked() {
        final HmacSigner signer = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.HEX);

        final byte[] raw = signer.signToBytes();
        for (int i = 0; i < raw.length; i++) {
            final byte[] tampered = raw.clone();
            tampered[i] ^= 0x01;
            assertFalse(signer.verify(tampered), "byte " + i + " was not checked");
        }
    }

    @Test
    public void theSecretAndMessageAreDefensivelyCopied() {
        final byte[] secret = "the secret".getBytes(StandardCharsets.UTF_8);
        final byte[] message = "the message".getBytes(StandardCharsets.UTF_8);

        final HmacSigner signer = new HmacSigner.Builder()
                .setEncoding(HmacSigner.Encoding.HEX)
                .setSecret(secret)
                .setMessage(message)
                .build();

        final String expected = new HmacSigner.Builder()
                .setEncoding(HmacSigner.Encoding.HEX)
                .setSecret("the secret")
                .setMessage("the message")
                .build()
                .sign();

        Arrays.fill(secret, (byte) 'X');
        Arrays.fill(message, (byte) 'X');

        assertEquals(expected, signer.sign());
    }

    @Test
    public void theStringOverloadsUseUtf8() {
        final String unicode = "é你好";

        final String fromString = new HmacSigner.Builder()
                .setEncoding(HmacSigner.Encoding.HEX)
                .setSecret(unicode)
                .setMessage(unicode)
                .build()
                .sign();

        final String fromBytes = new HmacSigner.Builder()
                .setEncoding(HmacSigner.Encoding.HEX)
                .setSecret(unicode.getBytes(StandardCharsets.UTF_8))
                .setMessage(unicode.getBytes(StandardCharsets.UTF_8))
                .build()
                .sign();

        assertEquals(fromBytes, fromString);
    }

    @Test
    public void theDefaultsAreSha256AndBase64() {
        final String signed = new HmacSigner.Builder()
                .setSecret(SECRET)
                .setMessage(MESSAGE)
                .build()
                .sign();

        final String explicit = new HmacSigner.Builder()
                .setAlgorithm(HmacSigner.Algorithm.HMAC_SHA256)
                .setEncoding(HmacSigner.Encoding.BASE64)
                .setSecret(SECRET)
                .setMessage(MESSAGE)
                .build()
                .sign();

        assertEquals(explicit, signed);
    }

    @Test
    public void anEmptyMessageIsSignable() {
        final HmacSigner signer = new HmacSigner.Builder()
                .setEncoding(HmacSigner.Encoding.HEX)
                .setSecret(SECRET)
                .setMessage("")
                .build();

        assertEquals(64, signer.sign().length());
        assertTrue(signer.verify(signer.sign()));
    }

    @Test
    public void anEmptySecretIsRejected() {
        final HmacSigner.Builder builder = new HmacSigner.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.setSecret(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> builder.setSecret(""));
    }

    @Test
    public void algorithmNamesAreTheJcaNames() {
        assertEquals("HmacSHA1", HmacSigner.Algorithm.HMAC_SHA1.getAlgorithmName());
        assertEquals("HmacSHA256", HmacSigner.Algorithm.HMAC_SHA256.getAlgorithmName());
        assertEquals("HmacSHA512", HmacSigner.Algorithm.HMAC_SHA512.getAlgorithmName());
    }

    @Test
    public void nullArgumentsThrow() {
        final HmacSigner.Builder builder = new HmacSigner.Builder();

        assertThrows(NullPointerException.class, () -> builder.setAlgorithm(null));
        assertThrows(NullPointerException.class, () -> builder.setEncoding(null));
        assertThrows(NullPointerException.class, () -> builder.setSecret((byte[]) null));
        assertThrows(NullPointerException.class, () -> builder.setSecret((String) null));
        assertThrows(NullPointerException.class, () -> builder.setMessage((byte[]) null));
        assertThrows(NullPointerException.class, () -> builder.setMessage((String) null));

        final HmacSigner signer = signer(HmacSigner.Algorithm.HMAC_SHA256,
                HmacSigner.Encoding.HEX);
        assertThrows(NullPointerException.class, () -> signer.verify((String) null));
        assertThrows(NullPointerException.class, () -> signer.verify((byte[]) null));
    }

    @Test
    public void buildWithoutASecretOrMessageThrows() {
        final HmacSigner.Builder noSecret = new HmacSigner.Builder().setMessage(MESSAGE);
        assertThrows(NullPointerException.class, noSecret::build);

        final HmacSigner.Builder noMessage = new HmacSigner.Builder().setSecret(SECRET);
        assertThrows(NullPointerException.class, noMessage::build);
    }

    private static HmacSigner signer(
            final HmacSigner.Algorithm algorithm,
            final HmacSigner.Encoding encoding) {
        return new HmacSigner.Builder()
                .setAlgorithm(algorithm)
                .setEncoding(encoding)
                .setSecret(SECRET)
                .setMessage(MESSAGE)
                .build();
    }

}
