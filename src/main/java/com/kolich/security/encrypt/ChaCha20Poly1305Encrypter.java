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

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * A wrapper on top of Java's ChaCha20-Poly1305 implementation, which provides symmetric
 * authenticated encryption of plain byte arrays. The construction is the one specified by
 * RFC 8439: the ChaCha20 stream cipher for confidentiality, the Poly1305 one-time
 * authenticator for integrity.
 *
 * <p>This is the sibling of {@link AESGaloisCounterEncrypter} and offers the same guarantees
 * through the same shape of API. Either is a sound choice. The reasons to prefer this one:
 *
 * <ul>
 *   <li>ChaCha20 is built from addition, rotation and exclusive-or on a fixed schedule, with
 *       no lookup tables, so it runs in constant time on every machine. AES without the
 *       AES-NI instruction falls back to table lookups whose timing depends on the key, and
 *       that is a side channel.</li>
 *   <li>Nonce reuse, while still a serious failure, is a contained one here; under GCM it is
 *       not. See the warning below.</li>
 *   <li>It is the default in TLS 1.3, WireGuard and SSH, so it is a well-exercised path.</li>
 * </ul>
 *
 * <p>The reason to prefer AES-GCM is speed on hardware that has AES-NI, which is to say most
 * hardware this is likely to run on; there the HotSpot intrinsic makes AES-GCM the faster of
 * the two by some margin. Neither is broken, and the decision rarely matters. What does
 * matter is not changing your mind after writing data, because the two formats are not
 * interchangeable.
 *
 * <p>{@link #encrypt()} generates a fresh random nonce on every call and prepends it to the
 * ciphertext, so the output is self-contained:
 *
 * <pre>
 *     [ nonce ][ ciphertext || authentication tag ]
 * </pre>
 *
 * <p>That is the same layout {@link AESGaloisCounterEncrypter} writes at its defaults, and the
 * lengths happen to agree as well, at {@value #NONCE_LENGTH_BYTES} and
 * {@value #TAG_LENGTH_BYTES} bytes. <strong>The payloads are still not interchangeable.</strong>
 * Handing one class the other's output returns {@code null}, like any other ciphertext it
 * cannot authenticate, and nothing in the payload records which cipher wrote it. A caller
 * that may hold data from both needs to keep that distinction itself.
 *
 * <p><strong>A nonce must never be reused with the same key.</strong> Two messages encrypted
 * under one key and nonce leak their exclusive-or, and they expose the Poly1305 one-time key
 * for that nonce, which lets an attacker forge messages that use it. This class therefore
 * does not accept a nonce from the caller; it draws a new one from {@link SecureRandom} per
 * {@link #encrypt()} call. The damage is at least bounded: the Poly1305 key is derived from
 * the key <em>and</em> the nonce, so what leaks is forgery under that one nonce. GCM is
 * harsher, as its authentication subkey does not depend on the nonce at all, so recovering
 * it once permits forgery under every nonce.
 *
 * <p>Random nonces carry a birthday bound. At {@value #NONCE_LENGTH_BYTES} bytes a repeat
 * becomes likely somewhere around 2^48 messages under a single key, which is far past any
 * plausible volume here, but it is the reason to rotate a key rather than use one forever.
 *
 * <p>Unlike {@link AESGaloisCounterEncrypter}, neither the nonce length nor the tag length is
 * configurable, because RFC 8439 fixes both: the nonce is always
 * {@value #NONCE_LENGTH_BYTES} bytes, the tag always {@value #TAG_LENGTH_BYTES}, and the key
 * always {@value #KEY_LENGTH_BYTES}. There is no truncated-tag variant to support and no
 * legacy length to read back.
 *
 * <p>Instances are built through {@link Builder} and are immutable. A single instance holds
 * one message, so build a new one per message rather than reusing it.
 */
public final class ChaCha20Poly1305Encrypter {

    /**
     * The nonce length, in bytes. RFC 8439 fixes this at 96 bits and the JDK accepts no
     * other length.
     */
    public static final int NONCE_LENGTH_BYTES = 12;

    /**
     * The Poly1305 authentication tag length, in bytes. Always the full 128 bits; the
     * construction defines no truncated variant.
     */
    public static final int TAG_LENGTH_BYTES = 16;

    /**
     * The key length, in bytes. ChaCha20 takes a 256 bit key and nothing else.
     */
    public static final int KEY_LENGTH_BYTES = 32;

    private static final String TRANSFORMATION = "ChaCha20-Poly1305";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKey secretKey_;

    private final byte[] message_;
    private final byte[] associatedData_;

    private ChaCha20Poly1305Encrypter(
            final SecretKey secretKey,
            final byte[] message,
            @Nullable final byte[] associatedData) {
        secretKey_ = Objects.requireNonNull(secretKey, "Secret key cannot be null.");
        // Defensive copies: the caller must not be able to mutate what is about to be
        // encrypted, or the data the authentication tag is computed over.
        message_ = Objects.requireNonNull(message, "Message cannot be null.").clone();
        associatedData_ = associatedData == null ? null : associatedData.clone();
    }

    /**
     * Encrypts the message under a freshly generated random nonce, returning the nonce
     * followed by the ciphertext and its authentication tag.
     *
     * @throws CipherException if the transformation is unavailable or the key is unusable
     */
    public byte[] encrypt() {
        // NEVER REUSE A NONCE WITH THE SAME KEY - a new one is drawn on every call.
        final byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(nonce);

        final Cipher cipher = newCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey_, new IvParameterSpec(nonce));

            if (associatedData_ != null) {
                cipher.updateAAD(associatedData_);
            }

            final byte[] encrypted = cipher.doFinal(message_);

            return ByteBuffer.allocate(nonce.length + encrypted.length)
                    .put(nonce)
                    .put(encrypted)
                    .array();
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new CipherException("Failed to encrypt message.", e);
        }
    }

    /**
     * Decrypts a payload produced by {@link #encrypt()}, returning the original message.
     *
     * <p>Returns {@code null} rather than throwing whenever the payload cannot be
     * authenticated: one too short to carry a nonce and a tag, one whose ciphertext or tag
     * has been tampered with, one encrypted under a different key or a different cipher, and
     * one whose associated data does not match. Poly1305 cannot tell these cases apart and
     * neither can a caller, which is the point: a failed decryption reveals nothing about
     * why it failed.
     *
     * @throws CipherException if the transformation is unavailable or the key is unusable
     */
    @Nullable
    public byte[] decrypt() {
        // The shortest possible payload is a nonce plus a tag over empty plaintext. Anything
        // shorter cannot authenticate, and the nonce cannot even be read off it.
        if (message_.length < NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES) {
            return null;
        }

        final Cipher cipher = newCipher();
        try {
            final IvParameterSpec parameterSpec =
                    new IvParameterSpec(message_, 0, NONCE_LENGTH_BYTES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey_, parameterSpec);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CipherException("Failed to initialize cipher for decryption.", e);
        }

        try {
            if (associatedData_ != null) {
                cipher.updateAAD(associatedData_);
            }

            return cipher.doFinal(message_, NONCE_LENGTH_BYTES, message_.length - NONCE_LENGTH_BYTES);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            // Authentication failed: tampered, truncated, wrong key, wrong cipher, or wrong
            // associated data. Not an error, just an invalid payload.
            return null;
        }
    }

    private Cipher newCipher() {
        try {
            return Cipher.getInstance(TRANSFORMATION);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CipherException("No such cipher transformation: " + TRANSFORMATION, e);
        }
    }

    public static final class Builder {

        private SecretKey secretKey_;

        private byte[] message_;
        private byte[] associatedData_;

        /**
         * Sets the secret key, which must be {@value #KEY_LENGTH_BYTES} bytes.
         *
         * <p>The length is checked here, rather than left to surface from {@code Cipher.init}
         * at encrypt time, so that a key of the wrong size is reported while the caller still
         * has the stack that produced it. A key that declines to expose its bytes, such as
         * one held in hardware, is passed through unchecked.
         */
        public Builder setSecretKey(
                final SecretKey secretKey) {
            Objects.requireNonNull(secretKey, "Secret key cannot be null.");

            final byte[] encoded = secretKey.getEncoded();
            if (encoded != null && encoded.length != KEY_LENGTH_BYTES) {
                throw new IllegalArgumentException("A ChaCha20 key must be exactly "
                        + KEY_LENGTH_BYTES + " bytes, but this one is " + encoded.length
                        + " bytes.");
            }

            secretKey_ = secretKey;
            return this;
        }

        public Builder setMessage(
                final byte[] message) {
            message_ = Objects.requireNonNull(message, "Message cannot be null.");
            return this;
        }

        /**
         * Sets additional data that is authenticated but not encrypted. It must be supplied
         * identically to {@link #decrypt()}, or decryption returns {@code null}.
         */
        public Builder setAssociatedData(
                final byte[] associatedData) {
            associatedData_ = Objects.requireNonNull(associatedData,
                    "Associated data cannot be null.");
            return this;
        }

        public ChaCha20Poly1305Encrypter build() {
            return new ChaCha20Poly1305Encrypter(secretKey_, message_, associatedData_);
        }

    }

}
