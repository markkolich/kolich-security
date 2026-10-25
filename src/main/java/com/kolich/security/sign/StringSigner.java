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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * Digitally signs plain strings using {@link ByteSigner}, returning a URL-safe Base64
 * encoding of the signed payload that is suitable for use in a cookie, a query parameter
 * or an API key.
 *
 * <p>Unlike {@link ByteSigner}, an instance of this class holds only keys rather than a
 * message, so a single instance is immutable, thread safe, and intended to be built once
 * and reused.
 *
 * <p>A signer built with only a public key can verify but not sign; one built with only a
 * private key can sign but not verify. Supply both to do both.
 *
 * <p>This class deliberately does no logging. The values that flow through a signer are
 * session payloads, tokens and API keys, and a library is not the right place to decide
 * whether such a value may be written to a log file. Callers that want a failure recorded
 * should catch {@link SignerException}, whose message never contains the value, or check
 * for the {@code null} return of {@link #verifyAndGet(String)}.
 */
public final class StringSigner {

    private final ByteSigner.Algorithm algorithm_;

    private final PublicKey publicKey_;
    private final PrivateKey privateKey_;

    private StringSigner(
            final ByteSigner.Algorithm algorithm,
            @Nullable final PublicKey publicKey,
            @Nullable final PrivateKey privateKey) {
        algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
        publicKey_ = publicKey;
        privateKey_ = privateKey;
    }

    /**
     * Signs the given string, returning a URL-safe Base64 encoded payload that carries both
     * the signature and the original string.
     *
     * @throws SignerException if the algorithm is unavailable or the private key is unusable
     */
    public String sign(
            @Nonnull final String toSign) {
        Objects.requireNonNull(toSign, "String to sign cannot be null.");

        final byte[] message = toSign.getBytes(StandardCharsets.UTF_8);
        final byte[] signed = new ByteSigner.Builder()
                .setAlgorithm(algorithm_)
                .setPrivateKey(privateKey_)
                .setMessage(message)
                .build()
                .sign();

        return Base64.getUrlEncoder().encodeToString(signed);
    }

    /**
     * Checks whether the given signed string carries a valid signature. Returns
     * {@code false} for any payload that is not valid, including one that is not even
     * well-formed Base64.
     *
     * @throws SignerException if the algorithm is unavailable or the public key is unusable
     */
    public boolean verify(
            @Nonnull final String signed) {
        return verifyAndGet(signed) != null;
    }

    /**
     * Verifies the signature on the given signed string and, if it is valid, returns the
     * original string. Returns {@code null} if the payload is not well-formed Base64, is
     * too short, or does not verify against the public key.
     *
     * @throws SignerException if the algorithm is unavailable or the public key is unusable
     */
    @Nullable
    public String verifyAndGet(
            @Nonnull final String signed) {
        Objects.requireNonNull(signed, "Signed string cannot be null.");

        final byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(signed);
        } catch (final IllegalArgumentException e) {
            // Not even valid Base64; it cannot be a payload this signer produced.
            return null;
        }

        final byte[] verified = new ByteSigner.Builder()
                .setAlgorithm(algorithm_)
                .setPublicKey(publicKey_)
                .setMessage(decoded)
                .build()
                .extract();
        if (verified == null) {
            return null;
        }

        return new String(verified, StandardCharsets.UTF_8);
    }

    public static final class Builder {

        private ByteSigner.Algorithm algorithm_ = ByteSigner.Algorithm.SHA512_WITH_RSA; // default

        private PublicKey publicKey_;
        private PrivateKey privateKey_;

        public Builder setAlgorithm(
                final ByteSigner.Algorithm algorithm) {
            algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
            return this;
        }

        public Builder setPublicKey(
                final PublicKey publicKey) {
            publicKey_ = publicKey;
            return this;
        }

        /**
         * Sets the public key from X.509 Base64 text, as {@link KeyDecoder} reads it,
         * assuming the {@value KeyDecoder#DEFAULT_KEY_ALGORITHM} key algorithm. Convenient
         * when the key pair lives in a configuration file.
         */
        public Builder setPublicKey(
                final String encodedPublicKey) {
            return setPublicKey(KeyDecoder.publicKey(encodedPublicKey));
        }

        /**
         * Sets the public key from X.509 Base64 text, as {@link KeyDecoder} reads it.
         */
        public Builder setPublicKey(
                final String encodedPublicKey,
                final String keyAlgorithm) {
            return setPublicKey(KeyDecoder.publicKey(encodedPublicKey, keyAlgorithm));
        }

        public Builder setPrivateKey(
                final PrivateKey privateKey) {
            privateKey_ = privateKey;
            return this;
        }

        /**
         * Sets the private key from PKCS#8 Base64 text, as {@link KeyDecoder} reads it,
         * assuming the {@value KeyDecoder#DEFAULT_KEY_ALGORITHM} key algorithm.
         */
        public Builder setPrivateKey(
                final String encodedPrivateKey) {
            return setPrivateKey(KeyDecoder.privateKey(encodedPrivateKey));
        }

        /**
         * Sets the private key from PKCS#8 Base64 text, as {@link KeyDecoder} reads it.
         */
        public Builder setPrivateKey(
                final String encodedPrivateKey,
                final String keyAlgorithm) {
            return setPrivateKey(KeyDecoder.privateKey(encodedPrivateKey, keyAlgorithm));
        }

        public StringSigner build() {
            return new StringSigner(algorithm_, publicKey_, privateKey_);
        }

    }

}
