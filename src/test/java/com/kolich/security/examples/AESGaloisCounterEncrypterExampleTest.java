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

import com.kolich.security.encrypt.AESGaloisCounterEncrypter;
import com.kolich.security.encrypt.PasswordEncrypter;
import com.kolich.security.encrypt.SecretKeys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Worked example of {@link AESGaloisCounterEncrypter}, which both conceals a message and
 * authenticates it. Unlike signing, the payload is unreadable without the key; unlike plain
 * encryption, a payload that has been altered refuses to decrypt at all.
 *
 * <p>The key is a stored random one, read from configuration through {@link SecretKeys}, so
 * encrypting and decrypting cost nothing per operation and are fine on a per-request path.
 * When the secret is a passphrase somebody types instead, use {@link PasswordEncrypter}.
 */
public final class AESGaloisCounterEncrypterExampleTest {

    /**
     * Produced once, offline, with {@code SecretKeys.toBase64(SecretKeys.random())} and then
     * pasted into a config file. This stands in for {@code config.getString("encrypt-key")}.
     */
    private static final String ENCRYPT_KEY_CONFIG_VALUE =
            SecretKeys.toBase64(SecretKeys.random());

    /**
     * Read the key once at startup. A {@link SecretKey} is immutable and thread safe, so it
     * belongs in a field rather than being re-read per message.
     */
    private static final SecretKey KEY = SecretKeys.fromBase64(ENCRYPT_KEY_CONFIG_VALUE);

    /**
     * The round trip. Note that each instance holds one message, so a new one gets built for
     * the encrypt and another for the decrypt.
     */
    @Test
    public void encryptsAndDecryptsWithStoredKey() {
        final byte[] plaintext = "{\"user\":\"mark\",\"roles\":[\"admin\"]}"
                .getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .build()
                .encrypt();

        final byte[] original = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .build()
                .decrypt();

        assertArrayEquals(plaintext, original);

        // The payload is self-contained - [ iv ][ ciphertext || tag ] - so nothing but the
        // key has to be stored alongside it. 12 bytes of IV plus 16 of tag is the overhead.
        assertEquals(plaintext.length + 12 + 16, encrypted.length);
    }

    /**
     * Encrypting the same bytes twice gives two different payloads, because a fresh random
     * IV is drawn on every call. That is not optional and the caller cannot override it.
     */
    @Test
    public void everyEncryptionDrawsFreshIv() {
        final byte[] plaintext = "the same message twice".getBytes(StandardCharsets.UTF_8);

        final byte[] first = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .build()
                .encrypt();
        final byte[] second = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .build()
                .encrypt();

        assertFalse(Arrays.equals(first, second));

        // Both still decrypt to the same thing.
        assertArrayEquals(plaintext, new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(second)
                .build()
                .decrypt());
    }

    /**
     * Associated data binds a ciphertext to a context, so a payload that is valid in one
     * place cannot be replayed into another. It is authenticated but not encrypted, and it
     * is not carried in the payload — the caller supplies it again to decrypt.
     */
    @Test
    public void bindsCiphertextToContextWithAssociatedData() {
        final byte[] plaintext = "session contents".getBytes(StandardCharsets.UTF_8);
        final byte[] context = "session:v1:user=mark".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .setAssociatedData(context)
                .build()
                .encrypt();

        // Same context: opens.
        assertArrayEquals(plaintext, new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData(context)
                .build()
                .decrypt());

        // Different user: does not, even though the key is right.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData("session:v1:user=someone-else".getBytes(StandardCharsets.UTF_8))
                .build()
                .decrypt());

        // Forgetting the associated data entirely is just another mismatch.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .build()
                .decrypt());
    }

    /**
     * Every failure looks the same from the outside: {@code decrypt()} returns {@code null}
     * and says nothing about why. Tampered, truncated, wrong key — GCM cannot tell them
     * apart and neither can a caller, which is deliberate.
     */
    @Test
    public void returnsNullForEveryKindOfInvalidPayload() {
        final byte[] plaintext = "do not modify".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .build()
                .encrypt();

        // One flipped bit in the ciphertext.
        final byte[] tampered = encrypted.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(tampered)
                .build()
                .decrypt());

        // Truncated.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(Arrays.copyOf(encrypted, encrypted.length - 4))
                .build()
                .decrypt());

        // A different key, which is also what a rotated-key payload looks like.
        final SecretKey otherKey = SecretKeys.random();
        assertNotEquals(KEY, otherKey);
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(otherKey)
                .setMessage(encrypted)
                .build()
                .decrypt());

        // So a caller checks for null; there is no exception to catch here.
        final byte[] decrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(tampered)
                .build()
                .decrypt();
        if (decrypted == null) {
            assertNull(decrypted);
        }
    }

}
