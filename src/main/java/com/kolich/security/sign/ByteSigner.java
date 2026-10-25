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

import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Objects;

/**
 * A signer that uses Java's built-in {@link Signature} classes to digitally sign a sequence
 * of bytes using a provided public-private key pair. The signature and the signed message
 * bytes are embedded in the resulting byte array as part of the payload, so the consumer of
 * this class does not need to pass around the signature and message separately.
 *
 * <p>The payload produced by {@link #sign()} is laid out as a length-prefixed signature
 * followed by the message body:
 *
 * <pre>
 *     [ 4-byte big-endian signature length ][ signature ][ message ]
 * </pre>
 *
 * <p>Prefixing the signature with its own length keeps the payload readable regardless of
 * how long the signature turns out to be, which in turn makes the format independent of the
 * key size. A signer that instead assumes a fixed signature length silently stops working
 * the day the key is rotated to a larger one.
 *
 * <p>This class has no dependencies beyond the JDK. Instances are built through
 * {@link Builder} and are immutable; a single instance holds one message, so build a new one
 * per message rather than reusing it.
 */
public final class ByteSigner {

    public enum Algorithm {

        SHA256_WITH_RSA("SHA256withRSA"),
        SHA512_WITH_RSA("SHA512withRSA");

        private final String algorithmName_;

        Algorithm(
                final String algorithmName) {
            algorithmName_ = algorithmName;
        }

        public String getAlgorithmName() {
            return algorithmName_;
        }

    }

    private final Algorithm algorithm_;

    private final PublicKey publicKey_;
    private final PrivateKey privateKey_;

    private final byte[] message_;

    private ByteSigner(
            final Algorithm algorithm,
            @Nullable final PublicKey publicKey,
            @Nullable final PrivateKey privateKey,
            final byte[] message) {
        algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
        publicKey_ = publicKey;
        privateKey_ = privateKey;
        // Defensive copy: the caller must not be able to swap the message out from under a
        // signature that has already been computed over it.
        message_ = Objects.requireNonNull(message, "Message cannot be null.").clone();
    }

    /**
     * Signs the message, returning a payload that carries the signature and the message
     * together. Requires that a private key was supplied.
     *
     * @throws SignerException if the algorithm is unavailable or the private key is unusable
     */
    public byte[] sign() {
        final PrivateKey privateKey = Objects.requireNonNull(privateKey_,
                "Private key cannot be null - cannot sign without a private key.");

        final Signature signature = newSignature();
        try {
            signature.initSign(privateKey);
            signature.update(message_);

            final byte[] signed = signature.sign();

            return ByteBuffer.allocate(Integer.BYTES + signed.length + message_.length)
                    .putInt(signed.length)
                    .put(signed)
                    .put(message_)
                    .array();
        } catch (final InvalidKeyException | SignatureException e) {
            throw new SignerException("Failed to sign message.", e);
        }
    }

    /**
     * Checks whether the signature embedded in the payload is valid for the message body
     * embedded alongside it. Requires that a public key was supplied.
     *
     * <p>Returns {@code false} rather than throwing for every shape of invalid payload: one
     * too short to hold a length prefix, one whose declared signature length is nonsensical,
     * one whose signature bytes are malformed, and one that simply does not verify.
     *
     * @throws SignerException if the algorithm is unavailable or the public key is unusable
     */
    public boolean verify() {
        final PublicKey publicKey = Objects.requireNonNull(publicKey_,
                "Public key cannot be null - cannot verify without a public key.");

        // Too short to hold a 4-byte length prefix plus anything at all.
        if (message_.length <= Integer.BYTES) {
            return false;
        }

        // The declared signature length is attacker-controlled, so it has to be range checked
        // before it is used as an offset into the payload.
        final int sigLength = ByteBuffer.wrap(message_).getInt();
        if (sigLength <= 0 || sigLength > message_.length - Integer.BYTES) {
            return false;
        }

        final Signature signature = newSignature();
        try {
            signature.initVerify(publicKey);
        } catch (final InvalidKeyException e) {
            throw new SignerException("Failed to initialize signature for verification.", e);
        }

        try {
            signature.update(message_, Integer.BYTES + sigLength,
                    message_.length - Integer.BYTES - sigLength);

            return signature.verify(message_, Integer.BYTES, sigLength);
        } catch (final SignatureException e) {
            // An improperly encoded signature is an invalid payload, not an error.
            return false;
        }
    }

    /**
     * Verifies that the signature on the payload is valid, and if so, extracts and returns
     * the signed message body. Otherwise, this method returns null.
     *
     * @throws SignerException if the algorithm is unavailable or the public key is unusable
     */
    @Nullable
    public byte[] extract() {
        if (!verify()) {
            return null;
        }

        final int sigLength = ByteBuffer.wrap(message_).getInt();

        return Arrays.copyOfRange(message_, Integer.BYTES + sigLength, message_.length);
    }

    private Signature newSignature() {
        final String algorithmName = algorithm_.getAlgorithmName();
        try {
            return Signature.getInstance(algorithmName);
        } catch (final NoSuchAlgorithmException e) {
            throw new SignerException("No such signature algorithm: " + algorithmName, e);
        }
    }

    public static final class Builder {

        private Algorithm algorithm_ = Algorithm.SHA512_WITH_RSA; // default

        private PublicKey publicKey_;
        private PrivateKey privateKey_;

        private byte[] message_;

        public Builder setAlgorithm(
                final Algorithm algorithm) {
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
         * assuming the {@value KeyDecoder#DEFAULT_KEY_ALGORITHM} key algorithm.
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

        public Builder setPrivateKey(
                final PrivateKey privateKey) {
            privateKey_ = privateKey;
            return this;
        }

        public Builder setMessage(
                final byte[] message) {
            message_ = Objects.requireNonNull(message, "Message cannot be null.");
            return this;
        }

        public ByteSigner build() {
            return new ByteSigner(algorithm_, publicKey_, privateKey_, message_);
        }

    }

}
