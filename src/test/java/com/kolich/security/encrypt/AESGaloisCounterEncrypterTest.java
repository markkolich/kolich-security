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

package com.kolich.security.encrypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.annotation.Nullable;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class AESGaloisCounterEncrypterTest {

    private static final SecretKey KEY = generateKey();

    private static final SecretKey OTHER_KEY = generateKey();

    private static final byte[] MESSAGE = "attack at dawn".getBytes(StandardCharsets.UTF_8);

    private static final byte[] ASSOCIATED_DATA = "v1;user=mark".getBytes(StandardCharsets.UTF_8);

    /**
     * The GCM authentication tag is 128 bits, so a ciphertext is 16 bytes longer than its
     * plaintext, on top of the prepended IV.
     */
    private static final int TAG_LENGTH_BYTES = 16;

    @ParameterizedTest
    @ValueSource(strings = {
        "attack at dawn",
        "a",
        "",
        "é你好🚀 unicode",
        "{\"session\":{\"user\":\"mark\",\"roles\":[\"admin\"]}}"
    })
    public void encryptThenDecryptRoundTrip(
            final String plaintext) {
        final byte[] message = plaintext.getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = encrypt(message);

        assertArrayEquals(message, decrypt(encrypted));
    }

    @Test
    public void theCiphertextIsTheIvPlusThePlaintextPlusTheTag() {
        final byte[] encrypted = encrypt(MESSAGE);

        assertEquals(AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES
                + MESSAGE.length + TAG_LENGTH_BYTES, encrypted.length);
    }

    @Test
    public void theDefaultIvLengthIsTheNistRecommendedTwelveBytes() {
        assertEquals(12, AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES);
        assertEquals(128, AESGaloisCounterEncrypter.DEFAULT_TAG_LENGTH_BITS);
    }

    /**
     * Reusing an IV with the same key breaks GCM completely, so a fresh one must be drawn
     * on every call. Encrypting identical plaintext repeatedly must therefore never produce
     * identical output.
     */
    @Test
    public void everyEncryptionUsesAFreshIv() {
        final int runs = 200;

        final Set<String> ciphertexts = new HashSet<>();
        final Set<String> ivs = new HashSet<>();
        for (int i = 0; i < runs; i++) {
            final byte[] encrypted = encrypt(MESSAGE);
            ciphertexts.add(Arrays.toString(encrypted));
            ivs.add(Arrays.toString(Arrays.copyOf(encrypted,
                    AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES)));

            // Each one still decrypts back to the same plaintext.
            assertArrayEquals(MESSAGE, decrypt(encrypted));
        }

        assertEquals(runs, ivs.size());
        assertEquals(runs, ciphertexts.size());
    }

    @Test
    public void tamperedCiphertextDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        // Flip a bit in the ciphertext body, just past the IV.
        encrypted[AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES] ^= 0x01;

        assertNull(decrypt(encrypted));
    }

    @Test
    public void tamperedIvDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        encrypted[0] ^= 0x01;

        assertNull(decrypt(encrypted));
    }

    @Test
    public void tamperedAuthenticationTagDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        encrypted[encrypted.length - 1] ^= 0x01;

        assertNull(decrypt(encrypted));
    }

    @Test
    public void truncatedPayloadDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        assertNull(decrypt(Arrays.copyOf(encrypted, encrypted.length - 1)));
        assertNull(decrypt(Arrays.copyOf(encrypted, encrypted.length / 2)));
    }

    /**
     * A payload no longer than the IV carries no ciphertext at all and must be rejected
     * rather than read off the end of the array.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 11, 12})
    public void payloadNoLongerThanTheIvDoesNotDecrypt(
            final int length) {
        assertNull(decrypt(new byte[length]));
    }

    @Test
    public void ciphertextEncryptedUnderAnotherKeyDoesNotDecrypt() {
        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(OTHER_KEY)
                .setMessage(MESSAGE)
                .build()
                .encrypt();

        assertNull(decrypt(encrypted));
    }

    @Test
    public void associatedDataRoundTripsWhenItMatches() {
        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .encrypt();

        final byte[] decrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .decrypt();

        assertArrayEquals(MESSAGE, decrypted);

        // Associated data is authenticated, not encrypted, so it does not pad the output.
        assertEquals(AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES
                + MESSAGE.length + TAG_LENGTH_BYTES, encrypted.length);
    }

    @Test
    public void mismatchedOrMissingAssociatedDataDoesNotDecrypt() {
        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .encrypt();

        // Different associated data.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData("v2;user=mark".getBytes(StandardCharsets.UTF_8))
                .build()
                .decrypt());

        // No associated data at all.
        assertNull(decrypt(encrypted));
    }

    @Test
    public void associatedDataIsRequiredOnlyIfItWasUsedToEncrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        // Supplying associated data that was not used to encrypt must also fail.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .decrypt());
    }

    /**
     * The IV length is configurable so that data written with a non-standard length can
     * still be read. A 128 <em>byte</em> IV is exercised deliberately, since that is the
     * kind of value a caller migrating off an older implementation is likely to meet.
     */
    @Test
    public void nonStandardIvLengthRoundTripsButOnlyAtThatLength() {
        final int legacyIvLengthBytes = 128;

        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setIvLengthBytes(legacyIvLengthBytes)
                .build()
                .encrypt();

        assertEquals(legacyIvLengthBytes + MESSAGE.length + TAG_LENGTH_BYTES, encrypted.length);

        // Reads back at the same IV length.
        final byte[] decrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setIvLengthBytes(legacyIvLengthBytes)
                .build()
                .decrypt();
        assertArrayEquals(MESSAGE, decrypted);

        // But not at the default length, which is exactly why changing the default is a
        // format break for anything already encrypted.
        assertNull(decrypt(encrypted));
    }

    @ParameterizedTest
    @ValueSource(ints = {96, 104, 112, 120, 128})
    public void everyPermittedTagLengthRoundTrips(
            final int tagLengthBits) {
        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setTagLengthBits(tagLengthBits)
                .build()
                .encrypt();

        assertEquals(AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES
                + MESSAGE.length + tagLengthBits / 8, encrypted.length);

        final byte[] decrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setTagLengthBits(tagLengthBits)
                .build()
                .decrypt();

        assertArrayEquals(MESSAGE, decrypted);
    }

    @Test
    public void theMessageIsDefensivelyCopied() {
        final byte[] mutable = "original".getBytes(StandardCharsets.UTF_8);

        final AESGaloisCounterEncrypter cipher = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(mutable)
                .build();

        Arrays.fill(mutable, (byte) 'X');

        final byte[] decrypted = decrypt(cipher.encrypt());

        assertNotNull(decrypted);
        assertEquals("original", new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    public void theCiphertextDoesNotContainThePlaintext() {
        final byte[] secret = "a very recognizable secret".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = encrypt(secret);

        final String asLatin1 = new String(encrypted, StandardCharsets.ISO_8859_1);
        assertFalse(asLatin1.contains("recognizable"));
        assertTrue(asLatin1.length() > 0);
    }

    @Test
    public void nullArgumentsThrow() {
        final AESGaloisCounterEncrypter.Builder builder = new AESGaloisCounterEncrypter.Builder();

        assertThrows(NullPointerException.class, () -> builder.setSecretKey(null));
        assertThrows(NullPointerException.class, () -> builder.setMessage(null));
        assertThrows(NullPointerException.class, () -> builder.setAssociatedData(null));
    }

    @Test
    public void buildWithoutAKeyOrMessageThrows() {
        final AESGaloisCounterEncrypter.Builder noKey = new AESGaloisCounterEncrypter.Builder()
                .setMessage(MESSAGE);
        assertThrows(NullPointerException.class, noKey::build);

        final AESGaloisCounterEncrypter.Builder noMessage = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY);
        assertThrows(NullPointerException.class, noMessage::build);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
    public void nonPositiveIvOrTagLengthIsRejected(
            final int length) {
        final AESGaloisCounterEncrypter.Builder builder = new AESGaloisCounterEncrypter.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.setIvLengthBytes(length));
        assertThrows(IllegalArgumentException.class, () -> builder.setTagLengthBits(length));
    }

    /**
     * A short random IV makes nonce reuse a certainty rather than a risk, and nonce reuse
     * takes GCM apart entirely, so the builder refuses one outright. A single byte IV has
     * only 256 values and repeats within about twenty messages.
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4, 8, 11})
    public void anIvShorterThanTheMinimumIsRejected(
            final int ivLengthBytes) {
        final AESGaloisCounterEncrypter.Builder builder = new AESGaloisCounterEncrypter.Builder();

        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> builder.setIvLengthBytes(ivLengthBytes));
        assertTrue(e.getMessage().contains(">= 12"), "unexpected message: " + e.getMessage());
    }

    @Test
    public void theMinimumIvLengthIsItselfAccepted() {
        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setIvLengthBytes(AESGaloisCounterEncrypter.MIN_IV_LENGTH_BYTES)
                .build()
                .encrypt();

        assertArrayEquals(MESSAGE, decrypt(encrypted));
    }

    /**
     * The tag range is enforced here rather than left to the JCA provider, because providers
     * differ on what they accept and a 32 bit tag would mean one-in-four-billion forgery odds
     * per attempt, with attempts repeatable.
     */
    @ParameterizedTest
    @ValueSource(ints = {8, 16, 32, 64, 88, 95, 127, 129, 136, 256})
    public void tagLengthOutsideWhatGcmDefinesIsRejected(
            final int tagLengthBits) {
        final AESGaloisCounterEncrypter.Builder builder = new AESGaloisCounterEncrypter.Builder();

        assertThrows(IllegalArgumentException.class,
                () -> builder.setTagLengthBits(tagLengthBits));
    }

    @Test
    public void theSafetyFloorsAreStable() {
        assertEquals(12, AESGaloisCounterEncrypter.MIN_IV_LENGTH_BYTES);
        assertEquals(96, AESGaloisCounterEncrypter.MIN_TAG_LENGTH_BITS);
        assertEquals(128, AESGaloisCounterEncrypter.MAX_TAG_LENGTH_BITS);

        // The default must not sit below its own floor.
        assertTrue(AESGaloisCounterEncrypter.DEFAULT_IV_LENGTH_BYTES
                >= AESGaloisCounterEncrypter.MIN_IV_LENGTH_BYTES);
        assertTrue(AESGaloisCounterEncrypter.DEFAULT_TAG_LENGTH_BITS
                >= AESGaloisCounterEncrypter.MIN_TAG_LENGTH_BITS);
    }

    private static byte[] encrypt(
            final byte[] message) {
        return new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(message)
                .build()
                .encrypt();
    }

    @Nullable
    private static byte[] decrypt(
            final byte[] payload) {
        return new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(payload)
                .build()
                .decrypt();
    }

    private static SecretKey generateKey() {
        try {
            final KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            return generator.generateKey();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES key generation is unavailable.", e);
        }
    }

}
