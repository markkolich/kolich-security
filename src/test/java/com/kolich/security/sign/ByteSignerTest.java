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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class ByteSignerTest {

    private static final KeyPair KEY_PAIR = generateKeyPair(2048);

    /**
     * A second key pair of the same size, used to prove that a payload signed by one key
     * does not verify under another.
     */
    private static final KeyPair OTHER_KEY_PAIR = generateKeyPair(2048);

    private static final byte[] MESSAGE = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @EnumSource(ByteSigner.Algorithm.class)
    public void signThenVerifyAndExtractRoundTrip(
            final ByteSigner.Algorithm algorithm) {
        final byte[] signed = signer(algorithm).setMessage(MESSAGE).build().sign();

        final ByteSigner verifier = verifier(algorithm).setMessage(signed).build();

        assertTrue(verifier.verify());
        assertArrayEquals(MESSAGE, verifier.extract());
    }

    /**
     * The regression test that matters most: the payload format must not depend on the key
     * size. A signer that assumes a fixed signature length passes at 2048 bits and fails at
     * 4096, because an RSA signature is exactly as long as the modulus.
     */
    @ParameterizedTest
    @ValueSource(ints = {1024, 2048, 3072, 4096})
    public void payloadFormatIsIndependentOfKeySize(
            final int keySize) {
        final KeyPair keyPair = generateKeyPair(keySize);

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(keyPair.getPrivate())
                .setMessage(MESSAGE)
                .build()
                .sign();

        final ByteSigner verifier = new ByteSigner.Builder()
                .setPublicKey(keyPair.getPublic())
                .setMessage(signed)
                .build();

        assertTrue(verifier.verify());
        assertArrayEquals(MESSAGE, verifier.extract());

        // The declared signature length must match the key size exactly.
        assertEquals(keySize / 8, ByteBuffer.wrap(signed).getInt());
    }

    @Test
    public void emptyMessageRoundTrips() {
        final byte[] empty = new byte[0];

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(empty)
                .build()
                .sign();

        final ByteSigner verifier = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(signed)
                .build();

        assertTrue(verifier.verify());
        assertArrayEquals(empty, verifier.extract());
    }

    @Test
    public void largeMessageRoundTrips() {
        final byte[] large = new byte[1024 * 512];
        new Random(42L).nextBytes(large);

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(large)
                .build()
                .sign();

        final ByteSigner verifier = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(signed)
                .build();

        assertTrue(verifier.verify());
        assertArrayEquals(large, verifier.extract());
    }

    @Test
    public void tamperedMessageBodyDoesNotVerify() {
        final byte[] signed = signedMessage();

        // Flip a bit in the message body, which sits after the length prefix and signature.
        final int sigLength = ByteBuffer.wrap(signed).getInt();
        signed[Integer.BYTES + sigLength] ^= 0x01;

        assertVerificationFails(signed);
    }

    @Test
    public void tamperedSignatureDoesNotVerify() {
        final byte[] signed = signedMessage();

        // Flip a bit inside the signature itself.
        signed[Integer.BYTES] ^= 0x01;

        assertVerificationFails(signed);
    }

    @Test
    public void truncatedPayloadDoesNotVerify() {
        final byte[] signed = signedMessage();

        assertVerificationFails(Arrays.copyOf(signed, signed.length - 1));
        assertVerificationFails(Arrays.copyOf(signed, signed.length / 2));
        assertVerificationFails(Arrays.copyOf(signed, Integer.BYTES + 1));
    }

    /**
     * A payload too short to even hold the four byte length prefix must be rejected rather
     * than read off the end of the array.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4})
    public void payloadShorterThanLengthPrefixDoesNotVerify(
            final int length) {
        assertVerificationFails(new byte[length]);
    }

    /**
     * The signature length is read straight out of attacker-supplied bytes, so a hostile
     * value must be rejected rather than used as an offset.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, 1_000_000, 97, 96, 10})
    public void hostileDeclaredSignatureLengthDoesNotVerify(
            final int declaredSigLength) {
        // A 100-byte payload: a 4-byte length prefix plus 96 bytes of nothing in particular.
        final byte[] payload = ByteBuffer.allocate(100)
                .putInt(declaredSigLength)
                .array();

        assertVerificationFails(payload);
    }

    @Test
    public void payloadSignedByAnotherKeyDoesNotVerify() {
        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(OTHER_KEY_PAIR.getPrivate())
                .setMessage(MESSAGE)
                .build()
                .sign();

        assertVerificationFails(signed);
    }

    @Test
    public void signWithoutPrivateKeyThrows() {
        final ByteSigner signer = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(MESSAGE)
                .build();

        assertThrows(NullPointerException.class, signer::sign);
    }

    @Test
    public void verifyWithoutPublicKeyThrows() {
        final ByteSigner verifier = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(signedMessage())
                .build();

        assertThrows(NullPointerException.class, verifier::verify);
        assertThrows(NullPointerException.class, verifier::extract);
    }

    @Test
    public void buildWithoutMessageThrows() {
        final ByteSigner.Builder builder = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate());

        assertThrows(NullPointerException.class, builder::build);
    }

    @Test
    public void nullArgumentsThrow() {
        final ByteSigner.Builder builder = new ByteSigner.Builder();

        assertThrows(NullPointerException.class, () -> builder.setAlgorithm(null));
        assertThrows(NullPointerException.class, () -> builder.setMessage(null));
    }

    /**
     * The builder takes a defensive copy of the message, so a caller cannot swap the bytes
     * out from under a signature that has already been computed over them.
     */
    @Test
    public void messageIsDefensivelyCopied() {
        final byte[] mutable = "original".getBytes(StandardCharsets.UTF_8);

        final ByteSigner signer = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(mutable)
                .build();

        // Mutate the caller's array after the signer was built.
        Arrays.fill(mutable, (byte) 'X');

        final byte[] signed = signer.sign();

        final byte[] extracted = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(signed)
                .build()
                .extract();

        assertNotNull(extracted);
        assertEquals("original", new String(extracted, StandardCharsets.UTF_8));
    }

    @Test
    public void algorithmNamesAreTheJcaNames() {
        assertEquals("SHA256withRSA", ByteSigner.Algorithm.SHA256_WITH_RSA.getAlgorithmName());
        assertEquals("SHA512withRSA", ByteSigner.Algorithm.SHA512_WITH_RSA.getAlgorithmName());
    }

    /**
     * A payload produced under one algorithm must not verify under the other.
     */
    @Test
    public void payloadDoesNotVerifyUnderADifferentAlgorithm() {
        final byte[] signed = signer(ByteSigner.Algorithm.SHA256_WITH_RSA)
                .setMessage(MESSAGE)
                .build()
                .sign();

        final ByteSigner verifier = verifier(ByteSigner.Algorithm.SHA512_WITH_RSA)
                .setMessage(signed)
                .build();

        assertFalse(verifier.verify());
        assertNull(verifier.extract());
    }

    private static void assertVerificationFails(
            final byte[] payload) {
        final ByteSigner verifier = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(payload)
                .build();

        assertFalse(verifier.verify());
        assertNull(verifier.extract());
    }

    private static byte[] signedMessage() {
        return new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(MESSAGE)
                .build()
                .sign();
    }

    private static ByteSigner.Builder signer(
            final ByteSigner.Algorithm algorithm) {
        return new ByteSigner.Builder()
                .setAlgorithm(algorithm)
                .setPrivateKey(KEY_PAIR.getPrivate());
    }

    private static ByteSigner.Builder verifier(
            final ByteSigner.Algorithm algorithm) {
        return new ByteSigner.Builder()
                .setAlgorithm(algorithm)
                .setPublicKey(KEY_PAIR.getPublic());
    }

    private static KeyPair generateKeyPair(
            final int keySize) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key pair generation is unavailable.", e);
        }
    }

}
