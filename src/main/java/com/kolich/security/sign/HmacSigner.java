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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

/**
 * Computes and checks HMAC (hash-based message authentication code) signatures over a
 * sequence of bytes using a shared secret.
 *
 * <p>An HMAC is symmetric: the same secret both produces and checks a signature, so both
 * parties hold it. That makes this the right tool for verifying a webhook from a third
 * party, or for an API request signing scheme in the style of AWS Signature V2. It is the
 * wrong tool when the checking party should not be able to mint signatures of its own; use
 * {@link ByteSigner} with a key pair for that.
 *
 * <p>Always check a signature with {@link #verify(String)} rather than comparing the output
 * of {@link #sign()} yourself. Comparing two signatures with {@code String.equals} or
 * {@code Arrays.equals} returns as soon as it reaches a differing byte, so how long the
 * comparison took leaks how much of a forged signature was correct, which in principle lets
 * an attacker recover a valid signature a byte at a time. {@link #verify(String)} compares
 * through {@link MessageDigest#isEqual} instead, which does not short circuit on content.
 *
 * <p>Instances are built through {@link Builder} and are immutable; a single instance holds
 * one message, so build a new one per message rather than reusing it.
 */
public final class HmacSigner {

    public enum Algorithm {

        /**
         * HMAC-SHA1. Still sound: HMAC does not rely on the collision resistance that makes
         * bare SHA-1 unfit for signatures. Kept for compatibility with existing schemes;
         * prefer {@link #HMAC_SHA256} for anything new.
         */
        HMAC_SHA1("HmacSHA1"),

        HMAC_SHA256("HmacSHA256"),

        HMAC_SHA512("HmacSHA512");

        private final String algorithmName_;

        Algorithm(
                final String algorithmName) {
            algorithmName_ = algorithmName;
        }

        public String getAlgorithmName() {
            return algorithmName_;
        }

    }

    public enum Encoding {

        /**
         * Standard Base64 with padding, the alphabet that uses {@code +} and {@code /}.
         */
        BASE64,

        /**
         * URL and filename safe Base64 with padding, the alphabet that uses {@code -} and
         * {@code _}.
         */
        BASE64_URL,

        /**
         * Lowercase hexadecimal. Decoding accepts either case.
         */
        HEX

    }

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    private final Algorithm algorithm_;
    private final Encoding encoding_;

    private final byte[] secret_;
    private final byte[] message_;

    private HmacSigner(
            final Algorithm algorithm,
            final Encoding encoding,
            final byte[] secret,
            final byte[] message) {
        algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
        encoding_ = Objects.requireNonNull(encoding, "Encoding cannot be null.");
        // Defensive copies; the caller must not be able to mutate either one out from under
        // a signature already computed over them.
        secret_ = Objects.requireNonNull(secret, "Secret cannot be null.").clone();
        message_ = Objects.requireNonNull(message, "Message cannot be null.").clone();
    }

    /**
     * Computes the signature and returns it in the configured encoding.
     *
     * @throws SignerException if the algorithm is unavailable or the secret is unusable
     */
    public String sign() {
        return encode(signToBytes());
    }

    /**
     * Computes the signature and returns the raw, unencoded bytes: 20 of them for
     * HMAC-SHA1, 32 for HMAC-SHA256 and 64 for HMAC-SHA512.
     *
     * @throws SignerException if the algorithm is unavailable or the secret is unusable
     */
    public byte[] signToBytes() {
        final String algorithmName = algorithm_.getAlgorithmName();

        final Mac mac;
        try {
            mac = Mac.getInstance(algorithmName);
        } catch (final NoSuchAlgorithmException e) {
            throw new SignerException("No such MAC algorithm: " + algorithmName, e);
        }

        try {
            mac.init(new SecretKeySpec(secret_, algorithmName));
        } catch (final InvalidKeyException e) {
            throw new SignerException("Failed to initialize MAC with the given secret.", e);
        }

        return mac.doFinal(message_);
    }

    /**
     * Checks an expected signature, in the configured encoding, against the signature this
     * signer computes, comparing in constant time.
     *
     * <p>Returns {@code false} rather than throwing when the expected signature is not
     * well-formed for the configured encoding, since a malformed signature is simply one
     * that does not match.
     *
     * @throws SignerException if the algorithm is unavailable or the secret is unusable
     */
    public boolean verify(
            final String expected) {
        Objects.requireNonNull(expected, "Expected signature cannot be null.");

        final byte[] decoded;
        try {
            decoded = decode(expected);
        } catch (final IllegalArgumentException e) {
            // Not well-formed in this encoding, so it cannot be a signature this signer
            // would ever produce.
            return false;
        }

        return verify(decoded);
    }

    /**
     * Checks an expected raw signature against the signature this signer computes,
     * comparing in constant time.
     *
     * @throws SignerException if the algorithm is unavailable or the secret is unusable
     */
    public boolean verify(
            final byte[] expected) {
        Objects.requireNonNull(expected, "Expected signature cannot be null.");

        // MessageDigest.isEqual does not return early on a differing byte. It does return
        // early when the two lengths differ, which is harmless: the length of a MAC is a
        // function of the algorithm, and the algorithm is not a secret.
        return MessageDigest.isEqual(signToBytes(), expected);
    }

    private String encode(
            final byte[] signature) {
        switch (encoding_) {
            case BASE64:
                return Base64.getEncoder().encodeToString(signature);
            case BASE64_URL:
                return Base64.getUrlEncoder().encodeToString(signature);
            case HEX:
                return toHex(signature);
            default:
                throw new SignerException("Unsupported encoding: " + encoding_);
        }
    }

    private byte[] decode(
            final String encoded) {
        switch (encoding_) {
            case BASE64:
                return Base64.getDecoder().decode(encoded);
            case BASE64_URL:
                return Base64.getUrlDecoder().decode(encoded);
            case HEX:
                return fromHex(encoded);
            default:
                throw new SignerException("Unsupported encoding: " + encoding_);
        }
    }

    private static String toHex(
            final byte[] bytes) {
        final StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (final byte octet : bytes) {
            sb.append(HEX_DIGITS[(octet >> 4) & 0x0f]).append(HEX_DIGITS[octet & 0x0f]);
        }

        return sb.toString();
    }

    private static byte[] fromHex(
            final String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length.");
        }

        final byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            final int high = Character.digit(hex.charAt(i * 2), 16);
            final int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Hex string contains a non-hex character.");
            }
            bytes[i] = (byte) ((high << 4) | low);
        }

        return bytes;
    }

    public static final class Builder {

        private Algorithm algorithm_ = Algorithm.HMAC_SHA256; // default
        private Encoding encoding_ = Encoding.BASE64; // default

        private byte[] secret_;
        private byte[] message_;

        public Builder setAlgorithm(
                final Algorithm algorithm) {
            algorithm_ = Objects.requireNonNull(algorithm, "Algorithm cannot be null.");
            return this;
        }

        public Builder setEncoding(
                final Encoding encoding) {
            encoding_ = Objects.requireNonNull(encoding, "Encoding cannot be null.");
            return this;
        }

        /**
         * Sets the shared secret, which must not be empty.
         */
        public Builder setSecret(
                final byte[] secret) {
            Objects.requireNonNull(secret, "Secret cannot be null.");
            if (secret.length == 0) {
                throw new IllegalArgumentException("Secret cannot be empty.");
            }
            secret_ = secret;
            return this;
        }

        /**
         * Sets the shared secret from the UTF-8 bytes of the given string.
         */
        public Builder setSecret(
                final String secret) {
            Objects.requireNonNull(secret, "Secret cannot be null.");
            return setSecret(secret.getBytes(StandardCharsets.UTF_8));
        }

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

        public HmacSigner build() {
            return new HmacSigner(algorithm_, encoding_, secret_, message_);
        }

    }

}
