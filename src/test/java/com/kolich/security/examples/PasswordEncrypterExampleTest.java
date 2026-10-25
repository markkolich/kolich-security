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

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Worked example of {@link PasswordEncrypter}, for when the secret is a passphrase somebody
 * types rather than a key that gets stored.
 *
 * <p>A password is not a key: it is short, low entropy and often reused, so it cannot be fed
 * to a cipher directly. This class stretches it with PBKDF2, encrypts with AES-GCM, and
 * writes the derivation parameters into the payload next to the ciphertext — so there is no
 * salt to manage and no key to keep.
 *
 * <p>Key derivation is deliberately expensive and the cost is paid on <em>every</em> call,
 * which makes this right for occasional work — a file, an export, a backup — and wrong for a
 * per-request path. For that, store a random key with {@link SecretKeys} and use
 * {@link AESGaloisCounterEncrypter}, which costs nothing per operation.
 */
public final class PasswordEncrypterExampleTest {

    private static final String PASSPHRASE = "correct horse battery staple";

    /**
     * Encrypting an export with nothing but a passphrase, and opening it again.
     */
    @Test
    public void encryptsAnExportWithAPassphrase() {
        final byte[] export = "id,path,bytes\n1,/photos/nye.jpg,84213\n"
                .getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSPHRASE)
                .setMessage(export)
                .build()
                .encrypt();

        // Nothing but the passphrase is needed to open it - no key file, no stored salt.
        final byte[] original = new PasswordEncrypter.Builder()
                .setPassword(PASSPHRASE)
                .setMessage(encrypted)
                .build()
                .decrypt();

        assertArrayEquals(export, original);

        // The header carries the parameters, so the payload is bigger than the plaintext by
        // more than a plain IV and tag.
        assertTrue(encrypted.length > export.length + 28);
    }

    /**
     * A wrong passphrase returns {@code null}, the same as a damaged payload. There is no
     * separate "wrong password" signal, because telling those apart would be a hint.
     */
    @Test
    public void returnsNullOnWrongPassphrase() {
        final byte[] message = "sensitive".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = new PasswordEncrypter.Builder()
                .setPassword(PASSPHRASE)
                .setMessage(message)
                .setIterationCount(1_000)
                .build()
                .encrypt();

        assertNull(new PasswordEncrypter.Builder()
                .setPassword("Correct horse battery staple")
                .setMessage(encrypted)
                .build()
                .decrypt());

        // And one flipped bit in the ciphertext is equally fatal, since the header is
        // authenticated as the cipher's associated data.
        final byte[] tampered = encrypted.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertNull(new PasswordEncrypter.Builder()
                .setPassword(PASSPHRASE)
                .setMessage(tampered)
                .build()
                .decrypt());
    }

    /**
     * The reason the parameters live in the payload: raising the cost later does not orphan
     * anything already written. {@code decrypt()} reads the parameters out of the payload it
     * was handed and ignores whatever the builder was told.
     */
    @Test
    public void oldPayloadsStillOpenAfterRaisingTheCost() {
        final byte[] message = "written years ago".getBytes(StandardCharsets.UTF_8);

        // Written long ago, cheaply, with a weaker digest.
        final byte[] old = new PasswordEncrypter.Builder()
                .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA1)
                .setPassword(PASSPHRASE)
                .setMessage(message)
                .setIterationCount(1_000)
                .setSaltLengthBytes(8)
                .build()
                .encrypt();

        // Read back by today's code, which is configured far more strictly. The builder
        // settings here apply to encryption only; this payload opens on its own terms.
        final byte[] recovered = new PasswordEncrypter.Builder()
                .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA512)
                .setPassword(PASSPHRASE)
                .setMessage(old)
                .setIterationCount(600_000)
                .build()
                .decrypt();

        assertArrayEquals(message, recovered);
    }

}
