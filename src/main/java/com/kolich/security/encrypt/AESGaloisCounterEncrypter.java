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
import com.kolich.security.sign.ByteSigner;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * A wrapper on top of Java's AES (Advanced Encryption Standard) GCM (Galois/Counter Mode)
 * implementation, which provides symmetric authenticated encryption of plain byte arrays.
 *
 * <p>Unlike {@link ByteSigner}, which proves who wrote a message but leaves it readable,
 * this class conceals the message as well as authenticating it. It needs a secret key that
 * both the writer and the reader hold, rather than a public-private key pair.
 *
 * <p>{@link #encrypt()} generates a fresh random initialization vector on every call and
 * prepends it to the ciphertext, so the output is self-contained:
 *
 * <pre>
 *     [ iv ][ ciphertext || authentication tag ]
 * </pre>
 *
 * <p><strong>An IV must never be reused with the same key.</strong> GCM fails
 * catastrophically on nonce reuse: two messages encrypted under the same key and IV leak
 * their XOR, and recovering the authentication subkey becomes possible, which lets an
 * attacker forge messages. This class therefore does not accept an IV from the caller; it
 * draws a new one from {@link SecureRandom} per {@link #encrypt()} call.
 *
 * <p>The default IV length is {@value #DEFAULT_IV_LENGTH_BYTES} bytes, which is what
 * NIST SP 800-38D specifies for GCM. Lengths other than 12 bytes are permitted by GCM but
 * are derived through GHASH rather than used directly, and buy nothing. The length is
 * configurable only so that data written by something that chose differently can still be
 * read back; see {@link Builder#setIvLengthBytes(int)}.
 *
 * <p>Instances are built through {@link Builder} and are immutable. A single instance holds
 * one message, so build a new one per message rather than reusing it.
 */
public final class AESGaloisCounterEncrypter {

    /**
     * The IV length, in bytes, that NIST SP 800-38D specifies for GCM.
     */
    public static final int DEFAULT_IV_LENGTH_BYTES = 12;

    /**
     * The authentication tag length, in bits. 128 is the full tag and the only length that
     * should be used without a specific reason to truncate.
     */
    public static final int DEFAULT_TAG_LENGTH_BITS = 128;

    /**
     * The shortest IV this class will accept, in bytes.
     *
     * <p>A short IV guarantees the one thing GCM cannot survive. IVs here are drawn at
     * random, so by the birthday bound a collision becomes likely after roughly the square
     * root of the IV space: a one byte IV repeats within about twenty messages, and a nonce
     * repeated under one key does not merely expose those two messages, it exposes the GHASH
     * authentication subkey and with it the ability to forge arbitrary messages. Twelve bytes
     * is both the NIST recommendation and the floor.
     */
    public static final int MIN_IV_LENGTH_BYTES = 12;

    /**
     * The shortest authentication tag this class will accept, in bits. A truncated tag is a
     * weaker forgery barrier, and GCM permits no less than this.
     */
    public static final int MIN_TAG_LENGTH_BITS = 96;

    /**
     * The longest authentication tag GCM defines, in bits.
     */
    public static final int MAX_TAG_LENGTH_BITS = 128;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKey secretKey_;

    private final byte[] message_;
    private final byte[] associatedData_;

    private final int ivLengthBytes_;
    private final int tagLengthBits_;

    private AESGaloisCounterEncrypter(
            final SecretKey secretKey,
            final byte[] message,
            @Nullable final byte[] associatedData,
            final int ivLengthBytes,
            final int tagLengthBits) {
        secretKey_ = Objects.requireNonNull(secretKey, "Secret key cannot be null.");
        // Defensive copies: the caller must not be able to mutate what is about to be
        // encrypted, or the data the authentication tag is computed over.
        message_ = Objects.requireNonNull(message, "Message cannot be null.").clone();
        associatedData_ = associatedData == null ? null : associatedData.clone();
        ivLengthBytes_ = ivLengthBytes;
        tagLengthBits_ = tagLengthBits;
    }

    /**
     * Encrypts the message under a freshly generated random IV, returning the IV followed
     * by the ciphertext and its authentication tag.
     *
     * @throws CipherException if the transformation is unavailable or the key is unusable
     */
    public byte[] encrypt() {
        // NEVER REUSE AN IV WITH THE SAME KEY - a new one is drawn on every call.
        final byte[] iv = new byte[ivLengthBytes_];
        SECURE_RANDOM.nextBytes(iv);

        final Cipher cipher = newCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey_, new GCMParameterSpec(tagLengthBits_, iv));

            if (associatedData_ != null) {
                cipher.updateAAD(associatedData_);
            }

            final byte[] encrypted = cipher.doFinal(message_);

            return ByteBuffer.allocate(iv.length + encrypted.length)
                    .put(iv)
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
     * authenticated: one too short to contain an IV, one whose ciphertext or tag has been
     * tampered with, one encrypted under a different key, and one whose associated data
     * does not match. GCM cannot tell these cases apart and neither can a caller, which is
     * the point: a failed decryption reveals nothing about why it failed.
     *
     * @throws CipherException if the transformation is unavailable or the key is unusable
     */
    @Nullable
    public byte[] decrypt() {
        // If the payload is no longer than the IV then it carries no ciphertext at all, so
        // there is nothing that could authenticate.
        if (message_.length <= ivLengthBytes_) {
            return null;
        }

        final Cipher cipher = newCipher();
        try {
            final GCMParameterSpec parameterSpec =
                    new GCMParameterSpec(tagLengthBits_, message_, 0, ivLengthBytes_);
            cipher.init(Cipher.DECRYPT_MODE, secretKey_, parameterSpec);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CipherException("Failed to initialize cipher for decryption.", e);
        }

        try {
            if (associatedData_ != null) {
                cipher.updateAAD(associatedData_);
            }

            return cipher.doFinal(message_, ivLengthBytes_, message_.length - ivLengthBytes_);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            // Authentication failed: tampered, truncated, wrong key, or wrong associated
            // data. Not an error, just an invalid payload.
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

        private int ivLengthBytes_ = DEFAULT_IV_LENGTH_BYTES;
        private int tagLengthBits_ = DEFAULT_TAG_LENGTH_BITS;

        public Builder setSecretKey(
                final SecretKey secretKey) {
            secretKey_ = Objects.requireNonNull(secretKey, "Secret key cannot be null.");
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

        /**
         * Sets the IV length in <em>bytes</em>, overriding the
         * {@value #DEFAULT_IV_LENGTH_BYTES} byte default. It must be at least
         * {@value #MIN_IV_LENGTH_BYTES}.
         *
         * <p>Reach for this only to read back data that was written with a longer IV. New
         * data should use the default. Anything shorter than the minimum is refused rather
         * than supported, because a short random IV makes nonce reuse a certainty and nonce
         * reuse takes GCM apart completely.
         */
        public Builder setIvLengthBytes(
                final int ivLengthBytes) {
            if (ivLengthBytes < MIN_IV_LENGTH_BYTES) {
                throw new IllegalArgumentException("IV length in bytes must be >= "
                        + MIN_IV_LENGTH_BYTES + ", but was: " + ivLengthBytes);
            }
            ivLengthBytes_ = ivLengthBytes;
            return this;
        }

        /**
         * Sets the authentication tag length in <em>bits</em>, overriding the
         * {@value #DEFAULT_TAG_LENGTH_BITS} bit default. GCM permits 96, 104, 112, 120 and
         * 128, which is every multiple of eight between {@value #MIN_TAG_LENGTH_BITS} and
         * {@value #MAX_TAG_LENGTH_BITS}; anything else is refused here.
         *
         * <p>A shorter tag is a proportionally weaker forgery barrier and there is rarely a
         * reason to shorten it. The range is checked here rather than left to the JCA
         * provider: providers differ on what they accept, and one that allowed a 32 bit tag
         * would be handing out one-in-four-billion forgery odds per attempt, with attempts
         * repeatable.
         */
        public Builder setTagLengthBits(
                final int tagLengthBits) {
            if (tagLengthBits < MIN_TAG_LENGTH_BITS || tagLengthBits > MAX_TAG_LENGTH_BITS
                    || tagLengthBits % 8 != 0) {
                throw new IllegalArgumentException("Tag length in bits must be a multiple of "
                        + "8 between " + MIN_TAG_LENGTH_BITS + " and " + MAX_TAG_LENGTH_BITS
                        + " inclusive, but was: " + tagLengthBits);
            }
            tagLengthBits_ = tagLengthBits;
            return this;
        }

        public AESGaloisCounterEncrypter build() {
            return new AESGaloisCounterEncrypter(secretKey_, message_, associatedData_,
                    ivLengthBytes_, tagLengthBits_);
        }

    }

}
