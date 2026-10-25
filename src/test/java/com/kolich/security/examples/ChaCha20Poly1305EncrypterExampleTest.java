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
import com.kolich.security.encrypt.ChaCha20Poly1305Encrypter;
import com.kolich.security.encrypt.SecretKeys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Worked example of {@link ChaCha20Poly1305Encrypter}, the RFC 8439 construction: the
 * ChaCha20 stream cipher for confidentiality, the Poly1305 one-time authenticator for
 * integrity.
 *
 * <p>The API is the same as {@link AESGaloisCounterEncrypter}'s, minus the length knobs,
 * because RFC 8439 fixes every length: the key is always 32 bytes, the nonce 12, the tag 16.
 * Either encrypter is a sound choice; what matters is not changing your mind after writing
 * data, because the two formats are not interchangeable.
 */
public final class ChaCha20Poly1305EncrypterExampleTest {

    /**
     * Produced once, offline, with {@code SecretKeys.toBase64(SecretKeys.randomChaCha20())}
     * and pasted into a config file.
     */
    private static final String ENCRYPT_KEY_CONFIG_VALUE =
            SecretKeys.toBase64(SecretKeys.randomChaCha20());

    /**
     * Naming the algorithm on the way in is what gets the key length checked here, with a
     * clear message, rather than much later inside {@code Cipher.init} with an obscure one.
     */
    private static final SecretKey KEY = SecretKeys.fromBase64(
            ENCRYPT_KEY_CONFIG_VALUE, SecretKeys.CHACHA20_KEY_ALGORITHM);

    /**
     * The round trip, identical in shape to the AES-GCM example.
     */
    @Test
    public void encryptsAndDecryptsWithStoredKey() {
        final byte[] plaintext = "{\"token\":\"abc123\"}".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .build()
                .encrypt();

        final byte[] original = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .build()
                .decrypt();

        assertArrayEquals(plaintext, original);

        // [ nonce ][ ciphertext || tag ], so 12 + 16 bytes of overhead - the same numbers
        // AES-GCM uses at its defaults.
        assertEquals(plaintext.length + ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES
                + ChaCha20Poly1305Encrypter.TAG_LENGTH_BYTES, encrypted.length);
    }

    /**
     * Associated data works exactly as it does on AES-GCM: authenticated, not encrypted, and
     * supplied again at decrypt time or the payload does not open.
     */
    @Test
    public void bindsCiphertextToContextWithAssociatedData() {
        final byte[] plaintext = "download authorization".getBytes(StandardCharsets.UTF_8);
        final byte[] context = "resource:/photos/nye.jpg".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .setAssociatedData(context)
                .build()
                .encrypt();

        assertArrayEquals(plaintext, new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData(context)
                .build()
                .decrypt());

        assertNull(new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData("resource:/photos/other.jpg".getBytes(StandardCharsets.UTF_8))
                .build()
                .decrypt());
    }

    /**
     * The two encrypters write payloads of identical shape at identical lengths, and they
     * still cannot read each other's output. Nothing in the payload records which one wrote
     * it, so a caller holding data from both has to keep that distinction itself.
     */
    @Test
    public void doesNotReadAesGcmPayloads() {
        final byte[] plaintext = "written by one, read by the other".getBytes(StandardCharsets.UTF_8);

        // Deliberately the same 32 raw bytes on both sides, to show that matching key
        // material is not what makes the formats compatible.
        final byte[] rawKey = KEY.getEncoded();
        final SecretKey asAesKey = SecretKeys.fromBase64(
                SecretKeys.toBase64(KEY), SecretKeys.DEFAULT_KEY_ALGORITHM);
        assertArrayEquals(rawKey, asAesKey.getEncoded());

        final byte[] fromAes = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(asAesKey)
                .setMessage(plaintext)
                .build()
                .encrypt();

        final byte[] fromChaCha = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(plaintext)
                .build()
                .encrypt();

        // Same length, same layout.
        assertEquals(fromAes.length, fromChaCha.length);

        // Neither opens the other's payload; it is simply one that does not authenticate.
        assertNull(new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(fromAes)
                .build()
                .decrypt());
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(asAesKey)
                .setMessage(fromChaCha)
                .build()
                .decrypt());

        // In practice: do not share key material between the two at all. Generate one key
        // per encrypter, which is what randomChaCha20() and random() are for.
        assertEquals(32, SecretKeys.randomChaCha20().getEncoded().length);
    }

    /**
     * A key of the wrong length is refused by the builder rather than accepted and failed
     * later, since RFC 8439 admits exactly one key size.
     */
    @Test
    public void rejectsKeyOfTheWrongLength() {
        final SecretKey tooShort = SecretKeys.random(128);

        assertThrows(IllegalArgumentException.class, () -> new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(tooShort));

        // Reading a wrong-length key from config fails at startup instead, with a message
        // that names the length it actually got.
        assertThrows(RuntimeException.class, () -> SecretKeys.fromBase64(
                SecretKeys.toBase64(tooShort), SecretKeys.CHACHA20_KEY_ALGORITHM));
    }

}
