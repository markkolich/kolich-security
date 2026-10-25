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

import com.kolich.security.sign.ByteSigner;
import com.kolich.security.sign.StringSigner;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Worked example of {@link ByteSigner}, the byte-oriented signer underneath
 * {@link StringSigner}. Use this one directly when what needs signing is binary rather than
 * text, or when the Base64 wrapper is in the way.
 *
 * <p>The important structural difference from {@link StringSigner}: an instance holds one
 * message, so a new one gets built per message rather than reused.
 */
public final class ByteSignerExampleTest {

    private static final KeyPair KEY_PAIR = generateKeyPair();
    private static final KeyPair OTHER_KEY_PAIR = generateKeyPair();

    /**
     * Sign a binary payload, then verify it and get the original bytes back.
     */
    @Test
    public void signsAndExtractsBinaryPayload() {
        final byte[] manifest = "resource=/photos/nye.jpg;expires=1790000000"
                .getBytes(StandardCharsets.UTF_8);

        // Signing needs the private key. The message goes into the builder too, which is why
        // this is built per message rather than held in a field.
        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(manifest)
                .build()
                .sign();

        // Verifying needs the public key, and a new instance built over the signed payload
        // rather than over the original message.
        final byte[] extracted = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(signed)
                .build()
                .extract();

        assertArrayEquals(manifest, extracted);
    }

    /**
     * The payload is self-contained: signature and message travel together, so there is no
     * second field to pass around and no chance of pairing the wrong two.
     */
    @Test
    public void payloadCarriesSignatureAndMessageTogether() {
        final byte[] message = "signature and message in one blob".getBytes(StandardCharsets.UTF_8);

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(message)
                .build()
                .sign();

        // [ 4-byte big-endian signature length ][ signature ][ message ]
        final int signatureLength = ByteBuffer.wrap(signed).getInt();
        assertEquals(Integer.BYTES + signatureLength + message.length, signed.length);

        final byte[] body = Arrays.copyOfRange(signed, Integer.BYTES + signatureLength, signed.length);
        assertArrayEquals(message, body);

        // The length prefix is what keeps the format independent of key size: an RSA
        // signature is as long as the modulus, so rotating 2048 -> 4096 changes it.
        assertEquals(256, signatureLength);
    }

    /**
     * A payload signed by somebody else's key does not verify, and nothing is handed back.
     */
    @Test
    public void rejectsPayloadSignedByAnotherKey() {
        final byte[] message = "minted elsewhere".getBytes(StandardCharsets.UTF_8);

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(OTHER_KEY_PAIR.getPrivate())
                .setMessage(message)
                .build()
                .sign();

        final ByteSigner verifier = new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(signed)
                .build();

        // verify() reports false and extract() returns null, for every shape of bad payload:
        // too short, nonsensical length prefix, malformed signature, or simply wrong key.
        assertFalse(verifier.verify());
        assertNull(verifier.extract());
    }

    /**
     * Truncating or editing the message body invalidates the signature over it.
     */
    @Test
    public void rejectsEditedMessageBody() {
        final byte[] message = "amount=100;to=mark".getBytes(StandardCharsets.UTF_8);

        final byte[] signed = new ByteSigner.Builder()
                .setPrivateKey(KEY_PAIR.getPrivate())
                .setMessage(message)
                .build()
                .sign();

        // Rewrite the last byte of the body.
        final byte[] tampered = signed.clone();
        tampered[tampered.length - 1] ^= 0x01;

        assertTrue(new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(signed)
                .build()
                .verify());
        assertFalse(new ByteSigner.Builder()
                .setPublicKey(KEY_PAIR.getPublic())
                .setMessage(tampered)
                .build()
                .verify());
    }

    private static KeyPair generateKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is required to be available.", e);
        }
    }

}
