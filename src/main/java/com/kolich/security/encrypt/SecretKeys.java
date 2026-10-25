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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Creates a {@link SecretKey} for {@link AESGaloisCounterEncrypter} or
 * {@link ChaCha20Poly1305Encrypter} from a key that was generated once and then stored, rather
 * than derived from a password.
 *
 * <p>This is the simpler of the two ways to get a key, and usually the better one. Generate
 * a key with {@link #random()}, print it with {@link #toBase64(SecretKey)}, paste that into
 * configuration, and read it back with {@link #fromBase64(String)}:
 *
 * <pre>
 *     // once, to produce the value that goes in the config file
 *     System.out.println(SecretKeys.toBase64(SecretKeys.random()));
 *
 *     // at startup
 *     final SecretKey key = SecretKeys.fromBase64(config.getString("encrypt-key"));
 * </pre>
 *
 * <p>This is the key source for a hot path: reading one costs nothing, so a service can
 * encrypt and decrypt per request. When the secret is instead a passphrase somebody types,
 * reach for {@link PasswordEncrypter}, which derives a key per payload and records the
 * parameters alongside the ciphertext.
 *
 * <p>A key handled this way is only as protected as the file it sits in. It is key material
 * in plain text; treat the file accordingly.
 */
public final class SecretKeys {

    /**
     * The default key length in bits, for AES-256.
     */
    public static final int DEFAULT_KEY_LENGTH_BITS = 256;

    /**
     * The algorithm keys are created for when none is given.
     */
    public static final String DEFAULT_KEY_ALGORITHM = "AES";

    /**
     * The algorithm name for a {@link ChaCha20Poly1305Encrypter} key.
     */
    public static final String CHACHA20_KEY_ALGORITHM = "ChaCha20";

    private static final Pattern WHITESPACE = Pattern.compile("\\s");

    // Cannot instantiate.
    private SecretKeys() {
    }

    /**
     * Generates a new random {@value #DEFAULT_KEY_LENGTH_BITS} bit
     * {@value #DEFAULT_KEY_ALGORITHM} key.
     */
    public static SecretKey random() {
        return random(DEFAULT_KEY_LENGTH_BITS, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Generates a new random {@value #DEFAULT_KEY_ALGORITHM} key of the given length in
     * bits, which for AES must be 128, 192 or 256.
     *
     * @throws CipherException if the algorithm is unavailable or rejects the length
     */
    public static SecretKey random(
            final int keyLengthBits) {
        return random(keyLengthBits, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Generates a new random key of the given length in bits for the given algorithm.
     *
     * @throws CipherException if the algorithm is unavailable or rejects the length
     */
    public static SecretKey random(
            final int keyLengthBits,
            final String keyAlgorithm) {
        Objects.requireNonNull(keyAlgorithm, "Key algorithm cannot be null.");

        try {
            final KeyGenerator generator = KeyGenerator.getInstance(keyAlgorithm);
            generator.init(keyLengthBits);
            return generator.generateKey();
        } catch (final NoSuchAlgorithmException e) {
            throw new CipherException("No such key algorithm: " + keyAlgorithm, e);
        } catch (final IllegalArgumentException e) {
            throw new CipherException("Invalid key length in bits for " + keyAlgorithm + ": "
                    + keyLengthBits, e);
        }
    }

    /**
     * Generates a new random key for {@link ChaCha20Poly1305Encrypter}, which is always
     * 256 bits.
     *
     * <p>A ChaCha20 key and a 256 bit AES key are both 32 random bytes, so nothing stops one
     * being handed to the other cipher. Do not: a key belongs to one cipher. Reusing key
     * material across two constructions buys nothing and forfeits the independence that
     * makes keeping a second cipher around worthwhile in the first place.
     *
     * @throws CipherException if the algorithm is unavailable
     */
    public static SecretKey randomChaCha20() {
        return random(ChaCha20Poly1305Encrypter.KEY_LENGTH_BYTES * 8, CHACHA20_KEY_ALGORITHM);
    }

    /**
     * Renders a key as Base64, which is the form to store in a configuration file.
     */
    public static String toBase64(
            final SecretKey secretKey) {
        Objects.requireNonNull(secretKey, "Secret key cannot be null.");

        final byte[] encoded = secretKey.getEncoded();
        if (encoded == null) {
            throw new CipherException("This secret key does not support encoding, so it "
                    + "cannot be rendered as Base64.");
        }

        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * Reads a Base64 encoded {@value #DEFAULT_KEY_ALGORITHM} key.
     *
     * @throws CipherException if the text is not Base64, or does not decode to a valid AES
     *     key length
     */
    public static SecretKey fromBase64(
            final String encoded) {
        return fromBase64(encoded, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Reads a Base64 encoded key for the given algorithm.
     *
     * <p>Whitespace is ignored and both the standard ({@code + /}) and URL-safe
     * ({@code - _}) Base64 alphabets are accepted, so a value that picked up a line break on
     * its way into a config file still reads. When the algorithm is AES the decoded length
     * is checked to be 16, 24 or 32 bytes, and when it is ChaCha20 to be exactly 32, because
     * a truncated or mistyped key otherwise fails much later with a far less obvious message.
     *
     * @throws CipherException if the text is not Base64, or is empty, or is the wrong length
     *     for AES or ChaCha20
     */
    public static SecretKey fromBase64(
            final String encoded,
            final String keyAlgorithm) {
        Objects.requireNonNull(encoded, "Encoded key cannot be null.");
        Objects.requireNonNull(keyAlgorithm, "Key algorithm cannot be null.");

        final byte[] keyBytes = decodeBase64(encoded);
        if (keyBytes.length == 0) {
            throw new CipherException("Encoded key decoded to zero bytes.");
        }

        if (DEFAULT_KEY_ALGORITHM.equalsIgnoreCase(keyAlgorithm)
                && keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new CipherException("An AES key must be 16, 24 or 32 bytes, but the "
                    + "encoded key decoded to " + keyBytes.length + " bytes.");
        }

        if (CHACHA20_KEY_ALGORITHM.equalsIgnoreCase(keyAlgorithm)
                && keyBytes.length != ChaCha20Poly1305Encrypter.KEY_LENGTH_BYTES) {
            throw new CipherException("A ChaCha20 key must be exactly "
                    + ChaCha20Poly1305Encrypter.KEY_LENGTH_BYTES + " bytes, but the encoded key "
                    + "decoded to " + keyBytes.length + " bytes.");
        }

        return new SecretKeySpec(keyBytes, keyAlgorithm);
    }

    private static byte[] decodeBase64(
            final String encoded) {
        final String stripped = WHITESPACE.matcher(encoded).replaceAll("");

        // Accept the URL-safe alphabet as well as the standard one.
        final String normalized = stripped.replace('-', '+').replace('_', '/');

        try {
            return Base64.getDecoder().decode(normalized);
        } catch (final IllegalArgumentException e) {
            throw new CipherException("Encoded key is not valid Base64.", e);
        }
    }

}
