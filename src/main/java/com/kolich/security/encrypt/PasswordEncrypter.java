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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encrypts and decrypts a sequence of bytes using nothing but a password, producing a
 * self-contained payload that carries everything needed to decrypt it again except the
 * password itself.
 *
 * <p>A password is not a key: it is short, low entropy and often reused, so it cannot be fed
 * to a cipher directly. This class stretches it into an AES-256 key with PBKDF2, encrypts
 * with AES-GCM, and writes the derivation parameters into the output alongside the
 * ciphertext.
 *
 * <pre>
 *     final byte[] encrypted = new PasswordEncrypter.Builder()
 *             .setPassword("correct horse battery staple")
 *             .setMessage(fileBytes)
 *             .build()
 *             .encrypt();
 *
 *     final byte[] original = new PasswordEncrypter.Builder()
 *             .setPassword("correct horse battery staple")
 *             .setMessage(encrypted)
 *             .build()
 *             .decrypt();   // null if the password is wrong or the payload is damaged
 * </pre>
 *
 * <p><strong>The salt and iteration count live in the payload, not in configuration.</strong>
 * That is the whole point of this class, and it is what makes it safe to change the defaults
 * later: {@link #decrypt()} reads the parameters out of the payload it was handed and ignores
 * whatever the builder was told, so raising {@link Builder#setIterationCount(int)} affects
 * new output only and everything already encrypted still opens. Deriving a key from a salt
 * and iteration count held in a config file has the opposite property, where changing either
 * one silently orphans all existing data.
 *
 * <p>Key derivation is deliberately expensive — the default of
 * {@value #DEFAULT_ITERATION_COUNT} iterations costs a sizeable fraction of a second — and
 * this class pays that cost on <em>every</em> {@link #encrypt()} and {@link #decrypt()} call,
 * because each payload has its own salt. That makes it right for occasional work: encrypting
 * a file, an export, a backup, or anything else guarded by a passphrase somebody types. It is
 * the wrong tool for a per-request path such as a session cookie; for that, store a random key
 * with {@link SecretKeys} and use {@link AESGaloisCounterEncrypter} directly, which costs
 * nothing per operation.
 *
 * <p>Instances are built through {@link Builder} and are immutable. A single instance holds
 * one message, so build a new one per message rather than reusing it.
 */
public final class PasswordEncrypter {

    /**
     * The OWASP recommended iteration count for PBKDF2-HMAC-SHA512.
     */
    public static final int DEFAULT_ITERATION_COUNT = 210_000;

    /**
     * The default salt length in bytes.
     */
    public static final int DEFAULT_SALT_LENGTH_BYTES = 16;

    /**
     * The shortest salt this class will encrypt with, in bytes.
     *
     * <p>A salt exists so that work done against one payload is worth nothing against the
     * next. A one byte salt leaves 256 possibilities, which is small enough to precompute
     * against, so the floor keeps the salt doing its job. Note that {@link #decrypt()}
     * deliberately does not apply this floor, since refusing to read a payload is a worse
     * outcome than having written it with a shorter salt than we would choose today.
     */
    public static final int MIN_SALT_LENGTH_BYTES = 8;

    /**
     * The largest iteration count {@link #decrypt()} will honour from a payload.
     *
     * <p>The iteration count in a payload is attacker controlled, and the whole purpose of
     * that number is to make work. Without a ceiling, a payload declaring two billion
     * iterations would be a denial of service against whoever tried to open it. A payload
     * above this limit is treated as invalid rather than obeyed.
     *
     * <p>The ceiling is deliberately close to the default rather than merely finite. A limit
     * far above the default still hands an attacker a large amplification factor: a payload
     * of a few dozen bytes buying seconds of CPU is a denial of service whether or not the
     * number is technically bounded. This limit is a little under five times
     * {@value #DEFAULT_ITERATION_COUNT}, which measured out around a quarter of a second per
     * attempt, and is far more headroom than a legitimate payload needs.
     */
    public static final int MAX_ITERATION_COUNT = 1_000_000;

    /**
     * The payload format this class writes.
     */
    private static final byte FORMAT_VERSION = 1;

    /**
     * Derived keys are always AES-256 and tags are always the full 128 bits. Neither is
     * configurable; the format version exists so that can change later if it ever needs to.
     */
    private static final int KEY_LENGTH_BITS = 256;

    private static final int IV_LENGTH_BYTES = 12;

    private static final int TAG_LENGTH_BITS = 128;

    /**
     * Version, algorithm id, iteration count, salt length and IV length.
     */
    private static final int HEADER_LENGTH_BYTES = 1 + 1 + Integer.BYTES + 1 + 1;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public enum Algorithm {

        PBKDF2_WITH_HMAC_SHA1((byte) 1, "PBKDF2WithHmacSHA1"),

        PBKDF2_WITH_HMAC_SHA256((byte) 2, "PBKDF2WithHmacSHA256"),

        PBKDF2_WITH_HMAC_SHA512((byte) 3, "PBKDF2WithHmacSHA512");

        private final byte id_;
        private final String algorithmName_;

        Algorithm(
                final byte id,
                final String algorithmName) {
            id_ = id;
            algorithmName_ = algorithmName;
        }

        public byte getId() {
            return id_;
        }

        public String getAlgorithmName() {
            return algorithmName_;
        }

        @Nullable
        private static Algorithm fromId(
                final byte id) {
            for (final Algorithm algorithm : values()) {
                if (algorithm.id_ == id) {
                    return algorithm;
                }
            }

            return null;
        }

    }

    private final Algorithm algorithm_;

    private final char[] password_;
    private final byte[] message_;

    private final int iterationCount_;
    private final int saltLengthBytes_;

    private PasswordEncrypter(
            final Algorithm algorithm,
            final char[] password,
            final byte[] message,
            final int iterationCount,
            final int saltLengthBytes) {
        algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
        // Defensive copies; the caller must not be able to mutate either one out from under
        // an operation already under way.
        password_ = Objects.requireNonNull(password, "Password cannot be null.").clone();
        message_ = Objects.requireNonNull(message, "Message cannot be null.").clone();
        iterationCount_ = iterationCount;
        saltLengthBytes_ = saltLengthBytes;
    }

    /**
     * Encrypts the message under a key derived from the password and a freshly generated
     * random salt, returning a payload that carries the derivation parameters, the IV, the
     * ciphertext and its authentication tag.
     *
     * @throws CipherException if an algorithm is unavailable or the derivation fails
     */
    public byte[] encrypt() {
        // A new salt per payload, so the same password never derives the same key twice.
        final byte[] salt = new byte[saltLengthBytes_];
        SECURE_RANDOM.nextBytes(salt);

        final SecretKey key =
                Pbkdf2.deriveKey(algorithm_, password_, salt, iterationCount_, KEY_LENGTH_BITS);

        final byte[] header = header(algorithm_, iterationCount_, salt);

        // The header is authenticated as associated data, so the parameters cannot be
        // altered in transit without the tag check failing.
        final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(key)
                .setMessage(message_)
                .setAssociatedData(header)
                .setIvLengthBytes(IV_LENGTH_BYTES)
                .setTagLengthBits(TAG_LENGTH_BITS)
                .build()
                .encrypt();

        return ByteBuffer.allocate(header.length + encrypted.length)
                .put(header)
                .put(encrypted)
                .array();
    }

    /**
     * Decrypts a payload produced by {@link #encrypt()}, deriving the key from the password
     * and the parameters recorded in the payload itself.
     *
     * <p>The algorithm, iteration count and salt come from the payload, so whatever the
     * builder was told about them is ignored here. A payload written with different
     * parameters still opens, which is what lets the defaults change without orphaning data.
     *
     * <p>Returns {@code null} rather than throwing for every shape of payload that cannot be
     * opened: a wrong password, a truncated or tampered payload, an unrecognised format
     * version or algorithm, a nonsensical length or iteration count, and a damaged
     * ciphertext. None of those is distinguishable from the others, by design.
     *
     * @throws CipherException if an algorithm is unavailable or the derivation fails
     */
    @Nullable
    public byte[] decrypt() {
        if (message_.length < HEADER_LENGTH_BYTES) {
            return null;
        }

        final ByteBuffer buffer = ByteBuffer.wrap(message_);

        if (buffer.get() != FORMAT_VERSION) {
            return null;
        }

        final Algorithm algorithm = Algorithm.fromId(buffer.get());
        if (algorithm == null) {
            return null;
        }

        // Both of these are attacker controlled, so they are range checked before use.
        final int iterationCount = buffer.getInt();
        if (iterationCount < 1 || iterationCount > MAX_ITERATION_COUNT) {
            return null;
        }

        final int saltLength = buffer.get() & 0xff;
        if (saltLength < 1 || message_.length < HEADER_LENGTH_BYTES + saltLength) {
            return null;
        }

        final byte[] salt = new byte[saltLength];
        buffer.get(salt);

        // Checked against the cipher's own floor, not merely against zero: the cipher now
        // refuses a short IV outright, and a hostile payload must come back as null from
        // here rather than as an IllegalArgumentException out of the builder.
        final int ivLength = buffer.get() & 0xff;
        if (ivLength < AESGaloisCounterEncrypter.MIN_IV_LENGTH_BYTES) {
            return null;
        }

        final int headerLength = HEADER_LENGTH_BYTES + saltLength;
        final byte[] body = Arrays.copyOfRange(message_, headerLength, message_.length);
        if (body.length <= ivLength) {
            return null;
        }

        final SecretKey key =
                Pbkdf2.deriveKey(algorithm, password_, salt, iterationCount, KEY_LENGTH_BITS);

        final byte[] header = Arrays.copyOf(message_, headerLength);

        return new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(key)
                .setMessage(body)
                .setAssociatedData(header)
                .setIvLengthBytes(ivLength)
                .setTagLengthBits(TAG_LENGTH_BITS)
                .build()
                .decrypt();
    }

    /**
     * Lays out the parameter header, which is written in the clear but authenticated as the
     * cipher's associated data. The IV length is recorded here, but the IV itself belongs to
     * the body that {@link AESGaloisCounterEncrypter} prepends it to.
     */
    private static byte[] header(
            final Algorithm algorithm,
            final int iterationCount,
            final byte[] salt) {
        return ByteBuffer.allocate(HEADER_LENGTH_BYTES + salt.length)
                .put(FORMAT_VERSION)
                .put(algorithm.getId())
                .putInt(iterationCount)
                .put((byte) salt.length)
                .put(salt)
                .put((byte) IV_LENGTH_BYTES)
                .array();
    }

    /**
     * PBKDF2 key derivation. Not public: a key derived from a password is only useful here,
     * where the salt and iteration count travel with the ciphertext. Exposing it would invite
     * callers to keep those in configuration instead, which is the arrangement this class
     * exists to avoid.
     */
    private static final class Pbkdf2 {

        // Cannot instantiate.
        private Pbkdf2() {
        }

        private static SecretKey deriveKey(
                final Algorithm algorithm,
                final char[] password,
                final byte[] salt,
                final int iterationCount,
                final int keyLengthBits) {
            final String algorithmName = algorithm.getAlgorithmName();

            final SecretKeyFactory factory;
            try {
                factory = SecretKeyFactory.getInstance(algorithmName);
            } catch (final NoSuchAlgorithmException e) {
                throw new CipherException("No such secret key factory algorithm: "
                        + algorithmName, e);
            }

            final PBEKeySpec keySpec =
                    new PBEKeySpec(password, salt, iterationCount, keyLengthBits);
            try {
                final byte[] derived = factory.generateSecret(keySpec).getEncoded();
                try {
                    return new SecretKeySpec(derived, SecretKeys.DEFAULT_KEY_ALGORITHM);
                } finally {
                    Arrays.fill(derived, (byte) 0);
                }
            } catch (final InvalidKeySpecException e) {
                throw new CipherException("Failed to derive a key from the given password.", e);
            } finally {
                // Zero out the copy of the password that PBEKeySpec holds internally.
                keySpec.clearPassword();
            }
        }

    }

    public static final class Builder {

        private Algorithm algorithm_ = Algorithm.PBKDF2_WITH_HMAC_SHA512; // default

        private char[] password_;
        private byte[] message_;

        private int iterationCount_ = DEFAULT_ITERATION_COUNT;
        private int saltLengthBytes_ = DEFAULT_SALT_LENGTH_BYTES;

        /**
         * Sets the key derivation algorithm used when encrypting. Decryption uses whichever
         * algorithm the payload records, so this does not affect reading existing data.
         */
        public Builder setAlgorithm(
                final Algorithm algorithm) {
            algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
            return this;
        }

        /**
         * Sets the password, for a caller that already holds one as characters rather than as
         * a string: {@link java.io.Console#readPassword()}, for instance.
         *
         * <p>Note that this class copies the characters and keeps that copy for as long as
         * the instance lives, so zeroing the array afterwards limits the exposure of the
         * caller's own array but does not scrub the password from the process.
         */
        public Builder setPassword(
                final char... password) {
            password_ = Objects.requireNonNull(password, "Password cannot be null.");
            return this;
        }

        /**
         * Sets the password from the given string.
         */
        public Builder setPassword(
                final String password) {
            Objects.requireNonNull(password, "Password cannot be null.");
            return setPassword(password.toCharArray());
        }

        /**
         * Sets the bytes to encrypt, or the payload to decrypt.
         */
        public Builder setMessage(
                final byte[] message) {
            message_ = Objects.requireNonNull(message, "Message cannot be null.");
            return this;
        }

        /**
         * Sets the message from the UTF-8 bytes of the given string.
         */
        public Builder setMessage(
                final String message) {
            Objects.requireNonNull(message, "Message cannot be null.");
            return setMessage(message.getBytes(StandardCharsets.UTF_8));
        }

        /**
         * Sets the PBKDF2 iteration count used when encrypting, overriding the
         * {@value #DEFAULT_ITERATION_COUNT} default.
         *
         * <p>This affects {@link #encrypt()} only. Decryption uses the count recorded in the
         * payload, so raising this never orphans data already encrypted with a lower one.
         */
        public Builder setIterationCount(
                final int iterationCount) {
            if (iterationCount < 1 || iterationCount > MAX_ITERATION_COUNT) {
                throw new IllegalArgumentException("Iteration count must be between 1 and "
                        + MAX_ITERATION_COUNT + " inclusive, but was: " + iterationCount);
            }
            iterationCount_ = iterationCount;
            return this;
        }

        /**
         * Sets the length of the random salt generated when encrypting, overriding the
         * {@value #DEFAULT_SALT_LENGTH_BYTES} byte default. It is recorded in a single byte
         * of the payload, so it must fit in {@value #MIN_SALT_LENGTH_BYTES} to 255 bytes.
         */
        public Builder setSaltLengthBytes(
                final int saltLengthBytes) {
            if (saltLengthBytes < MIN_SALT_LENGTH_BYTES || saltLengthBytes > 255) {
                throw new IllegalArgumentException("Salt length in bytes must be between "
                        + MIN_SALT_LENGTH_BYTES + " and 255 inclusive, but was: "
                        + saltLengthBytes);
            }
            saltLengthBytes_ = saltLengthBytes;
            return this;
        }

        public PasswordEncrypter build() {
            return new PasswordEncrypter(algorithm_, password_, message_, iterationCount_,
                    saltLengthBytes_);
        }

    }

}
