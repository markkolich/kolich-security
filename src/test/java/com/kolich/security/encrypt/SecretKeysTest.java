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

import com.kolich.security.exceptions.CipherException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class SecretKeysTest {

    /**
     * The whole workflow this class exists for: generate once, render to Base64 for a config
     * file, read it back in a later process.
     */
    @Test
    public void generateRenderAndReadBackRoundTrip() {
        final SecretKey generated = SecretKeys.random();

        final String asConfigValue = SecretKeys.toBase64(generated);
        final SecretKey readBack = SecretKeys.fromBase64(asConfigValue);

        assertArrayEquals(generated.getEncoded(), readBack.getEncoded());
        assertEquals("AES", readBack.getAlgorithm());
        assertEquals(generated, readBack);
    }

    /**
     * And the key that comes back has to actually work with the cipher, which is the only
     * reason any of this exists.
     */
    @Test
    public void theReadBackKeyWorksWithTheCipher() {
        final byte[] message = "round trip through a stored key".getBytes(StandardCharsets.UTF_8);

        final String asConfigValue = SecretKeys.toBase64(SecretKeys.random());

        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(SecretKeys.fromBase64(asConfigValue))
                .setMessage(message)
                .build()
                .encrypt();

        // A separate read of the same config value, as a fresh process would do.
        final byte[] decrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(SecretKeys.fromBase64(asConfigValue))
                .setMessage(encrypted)
                .build()
                .decrypt();

        assertArrayEquals(message, decrypted);

        // A different generated key must not open it.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(SecretKeys.random())
                .setMessage(encrypted)
                .build()
                .decrypt());
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    public void everyValidAesKeyLengthIsSupported(
            final int keyLengthBits) {
        final SecretKey key = SecretKeys.random(keyLengthBits);

        assertEquals(keyLengthBits / 8, key.getEncoded().length);
        assertArrayEquals(key.getEncoded(),
                SecretKeys.fromBase64(SecretKeys.toBase64(key)).getEncoded());
    }

    @Test
    public void generatedKeysAreRandom() {
        final int runs = 100;

        final Set<String> keys = new HashSet<>();
        for (int i = 0; i < runs; i++) {
            keys.add(SecretKeys.toBase64(SecretKeys.random()));
        }

        assertEquals(runs, keys.size());
    }

    @Test
    public void theDefaultsAre256BitAes() {
        assertEquals(256, SecretKeys.DEFAULT_KEY_LENGTH_BITS);
        assertEquals("AES", SecretKeys.DEFAULT_KEY_ALGORITHM);
        assertEquals(32, SecretKeys.random().getEncoded().length);
        assertEquals("AES", SecretKeys.random().getAlgorithm());
    }

    @Test
    public void bothBase64AlphabetsAreAccepted() {
        final SecretKey key = SecretKeys.random();
        final byte[] raw = key.getEncoded();

        final String standard = Base64.getEncoder().encodeToString(raw);
        final String urlSafe = Base64.getUrlEncoder().encodeToString(raw);

        assertArrayEquals(raw, SecretKeys.fromBase64(standard).getEncoded());
        assertArrayEquals(raw, SecretKeys.fromBase64(urlSafe).getEncoded());
    }

    /**
     * A value that picked up a line break on its way into a config file still has to read.
     */
    @Test
    public void whitespaceIsIgnored() {
        final SecretKey key = SecretKeys.random();
        final String encoded = SecretKeys.toBase64(key);

        final String wrapped = "  \n\t" + encoded.substring(0, 10) + "\n"
                + encoded.substring(10) + "  \n";

        assertArrayEquals(key.getEncoded(), SecretKeys.fromBase64(wrapped).getEncoded());
    }

    /**
     * A truncated or mistyped AES key is caught here with a clear message, rather than much
     * later inside {@code Cipher.init} with an obscure one.
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 8, 15, 17, 20, 31, 33, 64})
    public void wrongLengthAesKeyIsRejected(
            final int keyLengthBytes) {
        final String encoded = Base64.getEncoder().encodeToString(new byte[keyLengthBytes]);

        final CipherException e =
                assertThrows(CipherException.class, () -> SecretKeys.fromBase64(encoded));
        assertTrue(e.getMessage().contains("16, 24 or 32 bytes"),
                "unexpected message: " + e.getMessage());
    }

    /**
     * The length check applies to AES only; another algorithm may legitimately use some
     * other length.
     */
    @Test
    public void theLengthCheckAppliesOnlyToAes() {
        final String encoded = Base64.getEncoder().encodeToString(new byte[20]);

        final SecretKey key = SecretKeys.fromBase64(encoded, "HmacSHA1");

        assertEquals(20, key.getEncoded().length);
        assertEquals("HmacSHA1", key.getAlgorithm());
    }

    @Test
    public void theAesLengthCheckIsCaseInsensitiveOnTheAlgorithmName() {
        final String encoded = Base64.getEncoder().encodeToString(new byte[20]);

        assertThrows(CipherException.class, () -> SecretKeys.fromBase64(encoded, "aes"));
        assertThrows(CipherException.class, () -> SecretKeys.fromBase64(encoded, "AES"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "!!! not base64 !!!",
        "%%%%",
        "@@@@",
        "short"
    })
    public void textThatIsNotBase64IsRejected(
            final String notBase64) {
        assertThrows(CipherException.class, () -> SecretKeys.fromBase64(notBase64));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\n\t"})
    public void anEmptyKeyIsRejected(
            final String empty) {
        final CipherException e =
                assertThrows(CipherException.class, () -> SecretKeys.fromBase64(empty));
        assertTrue(e.getMessage().contains("zero bytes"), "unexpected message: " + e.getMessage());
    }

    @Test
    public void anUnknownKeyAlgorithmIsRejectedWhenGenerating() {
        assertThrows(CipherException.class, () -> SecretKeys.random(256, "NotAnAlgorithm"));
    }

    @Test
    public void anInvalidKeyLengthIsRejectedWhenGenerating() {
        assertThrows(CipherException.class, () -> SecretKeys.random(7));
        assertThrows(CipherException.class, () -> SecretKeys.random(0));
        assertThrows(CipherException.class, () -> SecretKeys.random(-1));
    }

    @Test
    public void nullArgumentsThrow() {
        assertThrows(NullPointerException.class, () -> SecretKeys.fromBase64(null));
        assertThrows(NullPointerException.class, () -> SecretKeys.fromBase64("AAAA", null));
        assertThrows(NullPointerException.class, () -> SecretKeys.toBase64(null));
        assertThrows(NullPointerException.class, () -> SecretKeys.random(256, null));
    }

    /**
     * Keys read back from configuration at two different lengths are both usable, since the
     * length travels with the key rather than being assumed.
     */
    @Test
    public void keysOfEveryLengthAreUsableWithTheCipher() {
        final byte[] message = "stored keys work".getBytes(StandardCharsets.UTF_8);

        for (final int keyLengthBits : new int[] {128, 192, 256}) {
            final String asConfigValue = SecretKeys.toBase64(SecretKeys.random(keyLengthBits));

            final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                    .setSecretKey(SecretKeys.fromBase64(asConfigValue))
                    .setMessage(message)
                    .build()
                    .encrypt();

            final byte[] decrypted = new AESGaloisCounterEncrypter.Builder()
                    .setSecretKey(SecretKeys.fromBase64(asConfigValue))
                    .setMessage(encrypted)
                    .build()
                    .decrypt();

            assertArrayEquals(message, decrypted);
        }
    }

}
