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

package com.kolich.security.sign;

import com.kolich.security.exceptions.SignerException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Turns Base64 text into a {@link PublicKey} or a {@link PrivateKey}, which is what it takes
 * to keep a key pair in a configuration file and hand it to {@link StringSigner} or
 * {@link ByteSigner}.
 *
 * <p>A public key is read as X.509 {@code SubjectPublicKeyInfo} and a private key as
 * {@code PKCS#8 PrivateKeyInfo}, which is what {@link java.security.Key#getEncoded()}
 * produces for each and therefore what {@code openssl} writes by default.
 *
 * <p>The Base64 is read leniently, because a key copied out of a {@code .pem} file picks up
 * line breaks and armor along the way. PEM {@code -----BEGIN ...-----} and
 * {@code -----END ...-----} lines are stripped, all whitespace is ignored, and both the
 * standard ({@code + /}) and URL-safe ({@code - _}) Base64 alphabets are accepted. What is
 * not accepted is a character that belongs to neither alphabet, so genuine corruption still
 * fails rather than being silently skipped.
 *
 * <p>Note that a private key in a config file is a private key in a config file: this class
 * makes no attempt to protect it, and it will sit in the process's heap once decoded.
 */
public final class KeyDecoder {

    /**
     * The key algorithm assumed when none is given. The signers in this package use RSA key
     * pairs.
     */
    public static final String DEFAULT_KEY_ALGORITHM = "RSA";

    private static final Pattern PEM_ARMOR = Pattern.compile("-----(BEGIN|END)[^-]*-----");

    private static final Pattern WHITESPACE = Pattern.compile("\\s");

    // Cannot instantiate.
    private KeyDecoder() {
    }

    /**
     * Decodes an X.509 encoded public key, assuming the {@value #DEFAULT_KEY_ALGORITHM}
     * algorithm.
     *
     * @throws SignerException if the text is not a well-formed key of that algorithm
     */
    public static PublicKey publicKey(
            final String encoded) {
        return publicKey(encoded, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Decodes an X.509 encoded public key.
     *
     * @throws SignerException if the text is not a well-formed key of that algorithm
     */
    public static PublicKey publicKey(
            final String encoded,
            final String keyAlgorithm) {
        Objects.requireNonNull(encoded, "Encoded key cannot be null.");

        final byte[] keyBytes = decodeBase64(encoded, "public");
        try {
            return keyFactory(keyAlgorithm).generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (final InvalidKeySpecException e) {
            throw new SignerException("Encoded public key is not a well-formed X.509 "
                    + keyAlgorithm + " key.", e);
        }
    }

    /**
     * Decodes a PKCS#8 encoded private key, assuming the {@value #DEFAULT_KEY_ALGORITHM}
     * algorithm.
     *
     * @throws SignerException if the text is not a well-formed key of that algorithm
     */
    public static PrivateKey privateKey(
            final String encoded) {
        return privateKey(encoded, DEFAULT_KEY_ALGORITHM);
    }

    /**
     * Decodes a PKCS#8 encoded private key.
     *
     * @throws SignerException if the text is not a well-formed key of that algorithm
     */
    public static PrivateKey privateKey(
            final String encoded,
            final String keyAlgorithm) {
        Objects.requireNonNull(encoded, "Encoded key cannot be null.");

        final byte[] keyBytes = decodeBase64(encoded, "private");
        try {
            return keyFactory(keyAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (final InvalidKeySpecException e) {
            throw new SignerException("Encoded private key is not a well-formed PKCS#8 "
                    + keyAlgorithm + " key.", e);
        }
    }

    private static KeyFactory keyFactory(
            final String keyAlgorithm) {
        Objects.requireNonNull(keyAlgorithm, "Key algorithm cannot be null.");

        try {
            return KeyFactory.getInstance(keyAlgorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new SignerException("No such key algorithm: " + keyAlgorithm, e);
        }
    }

    private static byte[] decodeBase64(
            final String encoded,
            final String which) {
        // Drop PEM armor first; it contains dashes, which the alphabet fix-up below would
        // otherwise turn into Base64 characters.
        final String unarmored = PEM_ARMOR.matcher(encoded).replaceAll("");
        final String stripped = WHITESPACE.matcher(unarmored).replaceAll("");

        // Accept the URL-safe alphabet as well as the standard one.
        final String normalized = stripped.replace('-', '+').replace('_', '/');

        try {
            return Base64.getDecoder().decode(normalized);
        } catch (final IllegalArgumentException e) {
            throw new SignerException("Encoded " + which + " key is not valid Base64.", e);
        }
    }

}
