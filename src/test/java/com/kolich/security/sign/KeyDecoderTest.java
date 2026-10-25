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

import com.kolich.security.exceptions.SignerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class KeyDecoderTest {

    private static final KeyPair KEY_PAIR = generateKeyPair();

    /**
     * The public key as URL-safe Base64, which is the encoding Onyx keeps in its config.
     */
    private static final String PUBLIC_URL_SAFE =
            Base64.getUrlEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded());

    private static final String PRIVATE_URL_SAFE =
            Base64.getUrlEncoder().encodeToString(KEY_PAIR.getPrivate().getEncoded());

    /**
     * The same keys as standard Base64, which is what {@code openssl} and most tooling emit.
     */
    private static final String PUBLIC_STANDARD =
            Base64.getEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded());

    private static final String PRIVATE_STANDARD =
            Base64.getEncoder().encodeToString(KEY_PAIR.getPrivate().getEncoded());

    @Test
    public void decodesTheUrlSafeAlphabet() {
        assertArrayEquals(KEY_PAIR.getPublic().getEncoded(),
                KeyDecoder.publicKey(PUBLIC_URL_SAFE).getEncoded());
        assertArrayEquals(KEY_PAIR.getPrivate().getEncoded(),
                KeyDecoder.privateKey(PRIVATE_URL_SAFE).getEncoded());
    }

    @Test
    public void decodesTheStandardAlphabet() {
        assertArrayEquals(KEY_PAIR.getPublic().getEncoded(),
                KeyDecoder.publicKey(PUBLIC_STANDARD).getEncoded());
        assertArrayEquals(KEY_PAIR.getPrivate().getEncoded(),
                KeyDecoder.privateKey(PRIVATE_STANDARD).getEncoded());
    }

    /**
     * The two alphabets differ only in two characters, so both must land on the same key.
     */
    @Test
    public void bothAlphabetsYieldTheSameKey() {
        assertEquals(KeyDecoder.publicKey(PUBLIC_STANDARD),
                KeyDecoder.publicKey(PUBLIC_URL_SAFE));
        assertEquals(KeyDecoder.privateKey(PRIVATE_STANDARD),
                KeyDecoder.privateKey(PRIVATE_URL_SAFE));
    }

    /**
     * A key pasted out of a {@code .pem} file arrives wrapped at 64 columns and wearing
     * armor, which must not stop it being read.
     */
    @Test
    public void decodesPemArmoredAndLineWrappedText() {
        final String pem = "-----BEGIN PUBLIC KEY-----\n"
                + wrap(PUBLIC_STANDARD)
                + "-----END PUBLIC KEY-----\n";

        assertArrayEquals(KEY_PAIR.getPublic().getEncoded(),
                KeyDecoder.publicKey(pem).getEncoded());

        final String privatePem = "-----BEGIN PRIVATE KEY-----\n"
                + wrap(PRIVATE_STANDARD)
                + "-----END PRIVATE KEY-----\n";

        assertArrayEquals(KEY_PAIR.getPrivate().getEncoded(),
                KeyDecoder.privateKey(privatePem).getEncoded());
    }

    @Test
    public void ignoresSurroundingWhitespace() {
        assertNotNull(KeyDecoder.publicKey("  \n\t" + PUBLIC_STANDARD + "\n  "));
        assertNotNull(KeyDecoder.privateKey("\n" + PRIVATE_STANDARD + "\t\n"));
    }

    /**
     * The decoded keys have to actually work, not merely parse.
     */
    @Test
    public void theDecodedKeysRoundTripThroughAStringSigner() {
        final StringSigner signer = new StringSigner.Builder()
                .setPublicKey(PUBLIC_URL_SAFE)
                .setPrivateKey(PRIVATE_URL_SAFE)
                .build();

        final String signed = signer.sign("signed with a key read from text");

        assertEquals("signed with a key read from text", signer.verifyAndGet(signed));
    }

    /**
     * A signer built from decoded text must interoperate with one built from the key objects
     * directly, which is what makes this safe for Onyx to adopt.
     */
    @Test
    public void signerFromTextInteroperatesWithOneFromKeyObjects() {
        final StringSigner fromText = new StringSigner.Builder()
                .setPublicKey(PUBLIC_URL_SAFE)
                .setPrivateKey(PRIVATE_URL_SAFE)
                .build();
        final StringSigner fromObjects = new StringSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setPrivateKey(KEY_PAIR.getPrivate())
                .build();

        assertEquals(fromObjects.sign("same bytes in"), fromText.sign("same bytes in"));
        assertEquals("same bytes in", fromObjects.verifyAndGet(fromText.sign("same bytes in")));
        assertEquals("same bytes in", fromText.verifyAndGet(fromObjects.sign("same bytes in")));
    }

    @Test
    public void theByteSignerBuilderTakesEncodedKeysToo() {
        final byte[] message = "bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(PRIVATE_URL_SAFE)
                .setMessage(message)
                .build()
                .sign();

        final byte[] extracted = new ByteSigner.Builder()
                .setPublicKey(PUBLIC_URL_SAFE)
                .setMessage(signed)
                .build()
                .extract();

        assertArrayEquals(message, extracted);
    }

    @Test
    public void theExplicitKeyAlgorithmOverloadWorks() {
        assertArrayEquals(KEY_PAIR.getPublic().getEncoded(),
                KeyDecoder.publicKey(PUBLIC_URL_SAFE, "RSA").getEncoded());
        assertArrayEquals(KEY_PAIR.getPrivate().getEncoded(),
                KeyDecoder.privateKey(PRIVATE_URL_SAFE, "RSA").getEncoded());
    }

    @Test
    public void theDefaultKeyAlgorithmIsRsa() {
        assertEquals("RSA", KeyDecoder.DEFAULT_KEY_ALGORITHM);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "!!! not base64 !!!",
        "short",
        "%%%%",
        "@@@@"
    })
    public void textThatIsNotBase64IsRejected(
            final String notBase64) {
        assertThrows(SignerException.class, () -> KeyDecoder.publicKey(notBase64));
        assertThrows(SignerException.class, () -> KeyDecoder.privateKey(notBase64));
    }

    @Test
    public void validBase64ThatIsNotAKeyIsRejected() {
        final String notAKey = Base64.getEncoder().encodeToString("this is not a key".getBytes(
                java.nio.charset.StandardCharsets.UTF_8));

        assertThrows(SignerException.class, () -> KeyDecoder.publicKey(notAKey));
        assertThrows(SignerException.class, () -> KeyDecoder.privateKey(notAKey));
    }

    /**
     * An X.509 public key is not a PKCS#8 private key, so feeding each to the wrong method
     * has to fail rather than quietly produce something unusable.
     */
    @Test
    public void thePublicAndPrivateEncodingsAreNotInterchangeable() {
        assertThrows(SignerException.class, () -> KeyDecoder.privateKey(PUBLIC_URL_SAFE));
        assertThrows(SignerException.class, () -> KeyDecoder.publicKey(PRIVATE_URL_SAFE));
    }

    @Test
    public void anUnknownKeyAlgorithmIsRejected() {
        assertThrows(SignerException.class,
                () -> KeyDecoder.publicKey(PUBLIC_URL_SAFE, "NotAnAlgorithm"));
    }

    @Test
    public void nullArgumentsThrow() {
        assertThrows(NullPointerException.class, () -> KeyDecoder.publicKey(null));
        assertThrows(NullPointerException.class, () -> KeyDecoder.privateKey(null));
        assertThrows(NullPointerException.class, () -> KeyDecoder.publicKey(PUBLIC_URL_SAFE, null));
        assertThrows(NullPointerException.class,
                () -> KeyDecoder.privateKey(PRIVATE_URL_SAFE, null));
    }

    private static String wrap(
            final String base64) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }

        return sb.toString();
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
