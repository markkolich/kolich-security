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
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class PasswordEncrypterTest {

    private static final String PASSWORD = "correct horse battery staple";

    private static final byte[] MESSAGE = "attack at dawn".getBytes(StandardCharsets.UTF_8);

    /**
     * PBKDF2 is slow on purpose, so the tests use a cheap iteration count. The default is
     * asserted as a constant rather than paid for in every test.
     */
    private static final int CHEAP_ITERATIONS = 1_000;

    /**
     * Header layout: version, algorithm id, 4-byte iteration count, salt length, salt, then
     * IV length.
     */
    private static final int VERSION_OFFSET = 0;

    private static final int ALGORITHM_OFFSET = 1;

    private static final int ITERATION_COUNT_OFFSET = 2;

    private static final int SALT_LENGTH_OFFSET = 6;

    private static final int SALT_OFFSET = 7;

    @ParameterizedTest
    @ValueSource(strings = {
        "attack at dawn",
        "a",
        "",
        "é你好🚀 unicode",
        "{\"export\":[1,2,3]}"
    })
    public void encryptThenDecryptRoundTrip(
            final String plaintext) {
        final byte[] message = plaintext.getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(message, decrypt(PASSWORD, encrypt(PASSWORD, message)));
    }

    @ParameterizedTest
    @EnumSource(PasswordEncrypter.Algorithm.class)
    public void everyAlgorithmRoundTrips(
            final PasswordEncrypter.Algorithm algorithm) {
        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setAlgorithm(algorithm)
                .setPassword(PASSWORD)
                .setMessage(MESSAGE)
                .setIterationCount(CHEAP_ITERATIONS)
                .build()
                .encrypt();

        assertArrayEquals(MESSAGE, decrypt(PASSWORD, encrypted));
    }

    /**
     * The property this class exists for. The salt, the iteration count and the algorithm all
     * travel inside the payload, so a reader configured completely differently still opens
     * data written earlier. Deriving from parameters held in configuration has the opposite
     * behaviour, where changing any of them orphans everything already encrypted.
     */
    @Test
    public void readerConfiguredDifferentlyStillOpensOlderPayloads() {
        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA1)
                .setPassword(PASSWORD)
                .setMessage(MESSAGE)
                .setIterationCount(1_000)
                .setSaltLengthBytes(8)
                .build()
                .encrypt();

        // Nothing here matches how it was written: different algorithm, a far higher
        // iteration count, a different salt length.
        final byte[] decrypted = new PasswordEncrypter.Builder()
                .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA512)
                .setPassword(PASSWORD)
                .setMessage(encrypted)
                .setIterationCount(500_000)
                .setSaltLengthBytes(32)
                .build()
                .decrypt();

        assertArrayEquals(MESSAGE, decrypted);
    }

    @Test
    public void theWrongPasswordDoesNotDecrypt() {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);

        assertNull(decrypt("the wrong password", encrypted));
        assertNull(decrypt("", encrypted));
        assertNull(decrypt(PASSWORD + " ", encrypted));
        assertNull(decrypt(PASSWORD.toUpperCase(java.util.Locale.US), encrypted));
    }

    /**
     * A fresh salt per payload, so the same password and plaintext never produce the same
     * output twice.
     */
    @Test
    public void everyPayloadUsesAFreshSalt() {
        final int runs = 25;

        final Set<String> payloads = new HashSet<>();
        final Set<String> salts = new HashSet<>();
        for (int i = 0; i < runs; i++) {
            final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
            payloads.add(Arrays.toString(encrypted));
            salts.add(Arrays.toString(Arrays.copyOfRange(encrypted, SALT_OFFSET,
                    SALT_OFFSET + PasswordEncrypter.DEFAULT_SALT_LENGTH_BYTES)));

            assertArrayEquals(MESSAGE, decrypt(PASSWORD, encrypted));
        }

        assertEquals(runs, salts.size());
        assertEquals(runs, payloads.size());
    }

    @Test
    public void theHeaderRecordsTheParametersThatWereUsed() {
        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA256)
                .setPassword(PASSWORD)
                .setMessage(MESSAGE)
                .setIterationCount(4_096)
                .setSaltLengthBytes(24)
                .build()
                .encrypt();

        assertEquals(1, encrypted[VERSION_OFFSET]);
        assertEquals(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA256.getId(),
                encrypted[ALGORITHM_OFFSET]);
        assertEquals(4_096, ByteBuffer.wrap(encrypted, ITERATION_COUNT_OFFSET,
                Integer.BYTES).getInt());
        assertEquals(24, encrypted[SALT_LENGTH_OFFSET]);
        assertEquals(12, encrypted[SALT_OFFSET + 24]); // the IV length

        // header + salt + iv length byte is accounted for; the rest is iv + ciphertext + tag.
        assertEquals(7 + 24 + 1 + 12 + MESSAGE.length + 16, encrypted.length);
    }

    /**
     * The header is authenticated as the cipher's associated data, so altering any recorded
     * parameter has to break the tag check rather than quietly change how the payload is read.
     */
    @Test
    public void tamperedHeaderDoesNotDecrypt() {
        // The iteration count, altered to another value that is still in range.
        final byte[] iterations = encrypt(PASSWORD, MESSAGE);
        ByteBuffer.wrap(iterations).putInt(ITERATION_COUNT_OFFSET, CHEAP_ITERATIONS + 1);
        assertNull(decrypt(PASSWORD, iterations));

        // The salt.
        final byte[] salt = encrypt(PASSWORD, MESSAGE);
        salt[SALT_OFFSET] ^= 0x01;
        assertNull(decrypt(PASSWORD, salt));

        // The algorithm id, swapped for another valid one.
        final byte[] algorithm = encrypt(PASSWORD, MESSAGE);
        algorithm[ALGORITHM_OFFSET] =
                PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA256.getId();
        assertNull(decrypt(PASSWORD, algorithm));
    }

    @Test
    public void tamperedCiphertextDoesNotDecrypt() {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);

        // Last byte is inside the authentication tag.
        encrypted[encrypted.length - 1] ^= 0x01;

        assertNull(decrypt(PASSWORD, encrypted));
    }

    @Test
    public void anUnrecognisedFormatVersionDoesNotDecrypt() {
        for (final byte version : new byte[] {0, 2, 3, (byte) 0xff}) {
            final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
            encrypted[VERSION_OFFSET] = version;
            assertNull(decrypt(PASSWORD, encrypted));
        }
    }

    @Test
    public void anUnrecognisedAlgorithmIdDoesNotDecrypt() {
        for (final byte id : new byte[] {0, 4, 99, (byte) 0xff}) {
            final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
            encrypted[ALGORITHM_OFFSET] = id;
            assertNull(decrypt(PASSWORD, encrypted));
        }
    }

    /**
     * The iteration count in a payload is attacker controlled and its entire purpose is to
     * make work, so a payload demanding an absurd amount of it must be rejected rather than
     * obeyed. Without the ceiling this is a denial of service against whoever opens it.
     */
    @Test
    public void anAbsurdIterationCountIsRejectedWithoutDoingTheWork() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            for (final int hostile : new int[] {Integer.MAX_VALUE, 2_000_000_000,
                    PasswordEncrypter.MAX_ITERATION_COUNT + 1}) {
                final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
                ByteBuffer.wrap(encrypted).putInt(ITERATION_COUNT_OFFSET, hostile);
                assertNull(decrypt(PASSWORD, encrypted), "iteration count " + hostile);
            }
        });
    }

    @Test
    public void nonPositiveIterationCountInThePayloadDoesNotDecrypt() {
        for (final int bad : new int[] {0, -1, Integer.MIN_VALUE}) {
            final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
            ByteBuffer.wrap(encrypted).putInt(ITERATION_COUNT_OFFSET, bad);
            assertNull(decrypt(PASSWORD, encrypted));
        }
    }

    @Test
    public void zeroLengthSaltInThePayloadDoesNotDecrypt() {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
        encrypted[SALT_LENGTH_OFFSET] = 0;

        assertNull(decrypt(PASSWORD, encrypted));
    }

    /**
     * A salt length that runs off the end of the payload must be rejected rather than used as
     * an offset.
     */
    @Test
    public void anOversizedSaltLengthDoesNotDecrypt() {
        for (final int oversized : new int[] {200, 255}) {
            final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
            encrypted[SALT_LENGTH_OFFSET] = (byte) oversized;
            assertNull(decrypt(PASSWORD, encrypted));
        }
    }

    @Test
    public void zeroLengthIvInThePayloadDoesNotDecrypt() {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
        encrypted[SALT_OFFSET + PasswordEncrypter.DEFAULT_SALT_LENGTH_BYTES] = 0;

        assertNull(decrypt(PASSWORD, encrypted));
    }

    /**
     * The cipher now refuses a short IV outright, so a payload declaring one has to come
     * back as null from decrypt rather than as an IllegalArgumentException escaping the
     * builder.
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4, 8, 11})
    public void payloadDeclaringAShortIvDoesNotDecrypt(
            final int ivLength) {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);
        encrypted[SALT_OFFSET + PasswordEncrypter.DEFAULT_SALT_LENGTH_BYTES] = (byte) ivLength;

        assertNull(decrypt(PASSWORD, encrypted));
    }

    @Test
    public void truncatedPayloadDoesNotDecrypt() {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);

        assertNull(decrypt(PASSWORD, Arrays.copyOf(encrypted, encrypted.length - 1)));
        assertNull(decrypt(PASSWORD, Arrays.copyOf(encrypted, encrypted.length / 2)));
        assertNull(decrypt(PASSWORD, Arrays.copyOf(encrypted, SALT_OFFSET)));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 5, 7, 8, 22})
    public void payloadShorterThanTheHeaderDoesNotDecrypt(
            final int length) {
        assertNull(decrypt(PASSWORD, new byte[length]));
    }

    @Test
    public void largeMessageRoundTrips() {
        final byte[] large = new byte[1024 * 256];
        new Random(42L).nextBytes(large);

        assertArrayEquals(large, decrypt(PASSWORD, encrypt(PASSWORD, large)));
    }

    @Test
    public void theCiphertextDoesNotContainThePlaintext() {
        final byte[] secret = "a very recognizable secret".getBytes(StandardCharsets.UTF_8);

        final String asLatin1 =
                new String(encrypt(PASSWORD, secret), StandardCharsets.ISO_8859_1);

        assertFalse(asLatin1.contains("recognizable"));
    }

    @Test
    public void theStringMessageOverloadUsesUtf8() {
        final String unicode = "é你好";

        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSWORD)
                .setMessage(unicode)
                .setIterationCount(CHEAP_ITERATIONS)
                .build()
                .encrypt();

        assertEquals(unicode,
                new String(decrypt(PASSWORD, encrypted), StandardCharsets.UTF_8));
    }

    @Test
    public void theCharArrayAndStringPasswordOverloadsAgree() {
        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSWORD.toCharArray())
                .setMessage(MESSAGE)
                .setIterationCount(CHEAP_ITERATIONS)
                .build()
                .encrypt();

        assertArrayEquals(MESSAGE, decrypt(PASSWORD, encrypted));
    }

    @Test
    public void thePasswordAndMessageAreDefensivelyCopied() {
        final char[] password = PASSWORD.toCharArray();
        final byte[] message = MESSAGE.clone();

        final PasswordEncrypter encrypter = new PasswordEncrypter.Builder()
                .setPassword(password)
                .setMessage(message)
                .setIterationCount(CHEAP_ITERATIONS)
                .build();

        Arrays.fill(password, 'X');
        Arrays.fill(message, (byte) 'X');

        final byte[] encrypted = encrypter.encrypt();

        assertArrayEquals(MESSAGE, decrypt(PASSWORD, encrypted));
    }

    @Test
    public void anInstanceCanEncryptMoreThanOnce() {
        final PasswordEncrypter encrypter = new PasswordEncrypter.Builder()
                .setPassword(PASSWORD)
                .setMessage(MESSAGE)
                .setIterationCount(CHEAP_ITERATIONS)
                .build();

        final byte[] first = encrypter.encrypt();
        final byte[] second = encrypter.encrypt();

        // Different salts, so different payloads, but both open.
        assertFalse(Arrays.equals(first, second));
        assertArrayEquals(MESSAGE, decrypt(PASSWORD, first));
        assertArrayEquals(MESSAGE, decrypt(PASSWORD, second));
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 16, 32, 64, 255})
    public void everyPermittedSaltLengthRoundTrips(
            final int saltLengthBytes) {
        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSWORD)
                .setMessage(MESSAGE)
                .setIterationCount(CHEAP_ITERATIONS)
                .setSaltLengthBytes(saltLengthBytes)
                .build()
                .encrypt();

        assertEquals(saltLengthBytes, encrypted[SALT_LENGTH_OFFSET] & 0xff);
        assertArrayEquals(MESSAGE, decrypt(PASSWORD, encrypted));
    }

    @Test
    public void theDefaultsAreStable() {
        assertEquals(210_000, PasswordEncrypter.DEFAULT_ITERATION_COUNT);
        assertEquals(16, PasswordEncrypter.DEFAULT_SALT_LENGTH_BYTES);
        assertEquals(1_000_000, PasswordEncrypter.MAX_ITERATION_COUNT);
        assertEquals(8, PasswordEncrypter.MIN_SALT_LENGTH_BYTES);
        assertEquals(1, PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA1.getId());
        assertEquals(2, PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA256.getId());
        assertEquals(3, PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA512.getId());
    }

    /**
     * The one test that pays the real production cost, proving the default iteration count is
     * what actually gets used when the builder is not told otherwise.
     */
    @Test
    public void theDefaultIterationCountIsUsedWhenNoneIsSet() {
        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSWORD)
                .setMessage(MESSAGE)
                .build()
                .encrypt();

        assertEquals(PasswordEncrypter.DEFAULT_ITERATION_COUNT,
                ByteBuffer.wrap(encrypted, ITERATION_COUNT_OFFSET, Integer.BYTES).getInt());

        final byte[] decrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSWORD)
                .setMessage(encrypted)
                .build()
                .decrypt();

        assertNotNull(decrypted);
        assertArrayEquals(MESSAGE, decrypted);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, 1_000_001, 10_000_000})
    public void anOutOfRangeIterationCountIsRejectedByTheBuilder(
            final int iterationCount) {
        final PasswordEncrypter.Builder builder = new PasswordEncrypter.Builder();

        assertThrows(IllegalArgumentException.class,
                () -> builder.setIterationCount(iterationCount));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 1, 2, 4, 7, 256, 1000, Integer.MIN_VALUE})
    public void anOutOfRangeSaltLengthIsRejectedByTheBuilder(
            final int saltLengthBytes) {
        final PasswordEncrypter.Builder builder = new PasswordEncrypter.Builder();

        assertThrows(IllegalArgumentException.class,
                () -> builder.setSaltLengthBytes(saltLengthBytes));
    }

    @Test
    public void nullArgumentsThrow() {
        final PasswordEncrypter.Builder builder = new PasswordEncrypter.Builder();

        assertThrows(NullPointerException.class, () -> builder.setAlgorithm(null));
        assertThrows(NullPointerException.class, () -> builder.setPassword((char[]) null));
        assertThrows(NullPointerException.class, () -> builder.setPassword((String) null));
        assertThrows(NullPointerException.class, () -> builder.setMessage((byte[]) null));
        assertThrows(NullPointerException.class, () -> builder.setMessage((String) null));
    }

    @Test
    public void buildWithoutAPasswordOrMessageThrows() {
        final PasswordEncrypter.Builder noPassword =
                new PasswordEncrypter.Builder().setMessage(MESSAGE);
        assertThrows(NullPointerException.class, noPassword::build);

        final PasswordEncrypter.Builder noMessage =
                new PasswordEncrypter.Builder().setPassword(PASSWORD);
        assertThrows(NullPointerException.class, noMessage::build);
    }

    @Test
    public void anEmptyPasswordIsPermitted() {
        // A terrible idea, but not this class's place to forbid reading data written with one.
        final byte[] encrypted = encrypt("", MESSAGE);

        assertArrayEquals(MESSAGE, decrypt("", encrypted));
        assertNull(decrypt(PASSWORD, encrypted));
    }

    @Test
    public void algorithmNamesAreTheJcaNames() {
        assertEquals("PBKDF2WithHmacSHA1",
                PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA1.getAlgorithmName());
        assertEquals("PBKDF2WithHmacSHA256",
                PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA256.getAlgorithmName());
        assertEquals("PBKDF2WithHmacSHA512",
                PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA512.getAlgorithmName());
    }

    /**
     * Nothing about the payload leaks the password, and the salt it carries is not the
     * password either.
     */
    @Test
    public void thePayloadDoesNotContainThePassword() {
        final byte[] encrypted = encrypt(PASSWORD, MESSAGE);

        final String asLatin1 = new String(encrypted, StandardCharsets.ISO_8859_1);

        assertFalse(asLatin1.contains(PASSWORD));
        assertFalse(asLatin1.contains("horse"));
        assertTrue(encrypted.length > SALT_OFFSET);
    }

    private static byte[] encrypt(
            final String password,
            final byte[] message) {
        return new PasswordEncrypter.Builder()
                .setPassword(password)
                .setMessage(message)
                .setIterationCount(CHEAP_ITERATIONS)
                .build()
                .encrypt();
    }

    @javax.annotation.Nullable
    private static byte[] decrypt(
            final String password,
            final byte[] payload) {
        return new PasswordEncrypter.Builder()
                .setPassword(password)
                .setMessage(payload)
                .setIterationCount(CHEAP_ITERATIONS)
                .build()
                .decrypt();
    }

}
