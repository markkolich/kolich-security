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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.annotation.Nullable;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class ChaCha20Poly1305EncrypterTest {

    private static final SecretKey KEY = generateKey();

    private static final SecretKey OTHER_KEY = generateKey();

    private static final byte[] MESSAGE = "attack at dawn".getBytes(StandardCharsets.UTF_8);

    private static final byte[] ASSOCIATED_DATA = "v1;user=mark".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @ValueSource(strings = {
        "attack at dawn",
        "a",
        "",
        "é你好🚀 unicode",
        "{\"session\":{\"user\":\"mark\",\"roles\":[\"admin\"]}}"
    })
    public void encryptThenDecryptRoundTrip(
            final String plaintext) {
        final byte[] message = plaintext.getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = encrypt(message);

        assertArrayEquals(message, decrypt(encrypted));
    }

    @Test
    public void theCiphertextIsTheNoncePlusThePlaintextPlusTheTag() {
        final byte[] encrypted = encrypt(MESSAGE);

        assertEquals(ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES + MESSAGE.length
                + ChaCha20Poly1305Encrypter.TAG_LENGTH_BYTES, encrypted.length);
    }

    /**
     * RFC 8439 fixes all three of these, so they are not configurable and must not drift.
     */
    @Test
    public void theLengthsFixedByTheRfcAreStable() {
        assertEquals(12, ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES);
        assertEquals(16, ChaCha20Poly1305Encrypter.TAG_LENGTH_BYTES);
        assertEquals(32, ChaCha20Poly1305Encrypter.KEY_LENGTH_BYTES);
    }

    /**
     * The AEAD test vector from RFC 8439 section 2.8.2, laid out in this class's own payload
     * framing and pushed through the public API.
     *
     * <p>This pins two things at once: that the construction really is the one the RFC
     * specifies, and that {@code [ nonce ][ ciphertext || tag ]} is read back the way it is
     * written. A reimplementation that agreed with itself but not with the RFC would pass
     * every round trip test in this file and fail only here.
     */
    @Test
    public void theRfc8439TestVectorDecrypts() {
        final byte[] key =
                hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        final byte[] nonce = hex("070000004041424344454647");
        final byte[] associatedData = hex("50515253c0c1c2c3c4c5c6c7");
        final byte[] ciphertextAndTag = hex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                + "3ff4def08e4b7a9de576d26586cec64b6116"
                + "1ae10b594f09e26a7e902ecbd0600691");

        final byte[] expected = ("Ladies and Gentlemen of the class of '99: If I could offer "
                + "you only one tip for the future, sunscreen would be it.")
                .getBytes(StandardCharsets.US_ASCII);
        assertEquals(114, expected.length);

        final byte[] payload = ByteBuffer.allocate(nonce.length + ciphertextAndTag.length)
                .put(nonce)
                .put(ciphertextAndTag)
                .array();

        final byte[] decrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(new SecretKeySpec(key, SecretKeys.CHACHA20_KEY_ALGORITHM))
                .setMessage(payload)
                .setAssociatedData(associatedData)
                .build()
                .decrypt();

        assertArrayEquals(expected, decrypted);
    }

    /**
     * The same vector without its associated data must not authenticate, which is what shows
     * the associated data is genuinely covered by the tag rather than ignored.
     */
    @Test
    public void theRfc8439TestVectorDoesNotDecryptWithoutItsAssociatedData() {
        final byte[] key =
                hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        final byte[] nonce = hex("070000004041424344454647");
        final byte[] ciphertextAndTag = hex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                + "3ff4def08e4b7a9de576d26586cec64b6116"
                + "1ae10b594f09e26a7e902ecbd0600691");

        final byte[] payload = ByteBuffer.allocate(nonce.length + ciphertextAndTag.length)
                .put(nonce)
                .put(ciphertextAndTag)
                .array();

        assertNull(new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(new SecretKeySpec(key, SecretKeys.CHACHA20_KEY_ALGORITHM))
                .setMessage(payload)
                .build()
                .decrypt());
    }

    /**
     * Reusing a nonce with the same key exposes the Poly1305 one-time key for that nonce, so
     * a fresh one must be drawn on every call. Encrypting identical plaintext repeatedly must
     * therefore never produce identical output.
     */
    @Test
    public void everyEncryptionUsesAFreshNonce() {
        final int runs = 200;

        final Set<String> ciphertexts = new HashSet<>();
        final Set<String> nonces = new HashSet<>();
        for (int i = 0; i < runs; i++) {
            final byte[] encrypted = encrypt(MESSAGE);
            ciphertexts.add(Arrays.toString(encrypted));
            nonces.add(Arrays.toString(Arrays.copyOf(encrypted,
                    ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES)));

            // Each one still decrypts back to the same plaintext.
            assertArrayEquals(MESSAGE, decrypt(encrypted));
        }

        assertEquals(runs, nonces.size());
        assertEquals(runs, ciphertexts.size());
    }

    @Test
    public void tamperedCiphertextDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        // Flip a bit in the ciphertext body, just past the nonce.
        encrypted[ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES] ^= 0x01;

        assertNull(decrypt(encrypted));
    }

    @Test
    public void tamperedNonceDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        encrypted[0] ^= 0x01;

        assertNull(decrypt(encrypted));
    }

    @Test
    public void tamperedAuthenticationTagDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        encrypted[encrypted.length - 1] ^= 0x01;

        assertNull(decrypt(encrypted));
    }

    @Test
    public void truncatedPayloadDoesNotDecrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        assertNull(decrypt(Arrays.copyOf(encrypted, encrypted.length - 1)));
        assertNull(decrypt(Arrays.copyOf(encrypted, encrypted.length / 2)));
    }

    /**
     * A payload shorter than a nonce plus a tag cannot authenticate whatever it contains, and
     * must be rejected rather than read off the end of the array.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 11, 12, 16, 27})
    public void payloadTooShortToCarryANonceAndTagDoesNotDecrypt(
            final int length) {
        assertNull(decrypt(new byte[length]));
    }

    /**
     * A nonce plus a full tag and no ciphertext at all is the shortest well-formed payload,
     * and it is exactly what encrypting an empty message produces.
     */
    @Test
    public void theShortestWellFormedPayloadIsANonceAndATag() {
        final byte[] encrypted = encrypt(new byte[0]);

        assertEquals(ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES
                + ChaCha20Poly1305Encrypter.TAG_LENGTH_BYTES, encrypted.length);
        assertArrayEquals(new byte[0], decrypt(encrypted));

        // Random bytes of that same length are not, essentially ever, a valid payload.
        assertNull(decrypt(new byte[encrypted.length]));
    }

    @Test
    public void ciphertextEncryptedUnderAnotherKeyDoesNotDecrypt() {
        final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(OTHER_KEY)
                .setMessage(MESSAGE)
                .build()
                .encrypt();

        assertNull(decrypt(encrypted));
    }

    /**
     * This class and {@link AESGaloisCounterEncrypter} write the same layout at the same
     * lengths, and nothing in a payload says which one produced it. Neither will read the
     * other's output, so this pins that a mix-up fails closed rather than quietly returning
     * rubbish. The same raw key bytes are used on both sides so that the formats are what is
     * being tested, not the keys.
     */
    @Test
    public void thisCipherAndAesGcmDoNotReadEachOthersPayloads() {
        final byte[] raw = new byte[ChaCha20Poly1305Encrypter.KEY_LENGTH_BYTES];
        Arrays.fill(raw, (byte) 0x2a);

        final SecretKey chaChaKey = new SecretKeySpec(raw, SecretKeys.CHACHA20_KEY_ALGORITHM);
        final SecretKey aesKey = new SecretKeySpec(raw, SecretKeys.DEFAULT_KEY_ALGORITHM);

        final byte[] fromChaCha = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(chaChaKey)
                .setMessage(MESSAGE)
                .build()
                .encrypt();

        final byte[] fromAes = new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(aesKey)
                .setMessage(MESSAGE)
                .build()
                .encrypt();

        // Identical framing and identical overall length...
        assertEquals(fromChaCha.length, fromAes.length);

        // ...and still mutually unreadable.
        assertNull(new AESGaloisCounterEncrypter.Builder()
                .setSecretKey(aesKey)
                .setMessage(fromChaCha)
                .build()
                .decrypt());

        assertNull(new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(chaChaKey)
                .setMessage(fromAes)
                .build()
                .decrypt());
    }

    @Test
    public void associatedDataRoundTripsWhenItMatches() {
        final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .encrypt();

        final byte[] decrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .decrypt();

        assertArrayEquals(MESSAGE, decrypted);

        // Associated data is authenticated, not encrypted, so it does not pad the output.
        assertEquals(ChaCha20Poly1305Encrypter.NONCE_LENGTH_BYTES + MESSAGE.length
                + ChaCha20Poly1305Encrypter.TAG_LENGTH_BYTES, encrypted.length);
    }

    @Test
    public void mismatchedOrMissingAssociatedDataDoesNotDecrypt() {
        final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .encrypt();

        // Different associated data.
        assertNull(new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData("v2;user=mark".getBytes(StandardCharsets.UTF_8))
                .build()
                .decrypt());

        // No associated data at all.
        assertNull(decrypt(encrypted));
    }

    @Test
    public void associatedDataIsRequiredOnlyIfItWasUsedToEncrypt() {
        final byte[] encrypted = encrypt(MESSAGE);

        // Supplying associated data that was not used to encrypt must also fail.
        assertNull(new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(encrypted)
                .setAssociatedData(ASSOCIATED_DATA)
                .build()
                .decrypt());
    }

    @Test
    public void theMessageIsDefensivelyCopied() {
        final byte[] mutable = "original".getBytes(StandardCharsets.UTF_8);

        final ChaCha20Poly1305Encrypter cipher = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(mutable)
                .build();

        Arrays.fill(mutable, (byte) 'X');

        final byte[] decrypted = decrypt(cipher.encrypt());

        assertNotNull(decrypted);
        assertEquals("original", new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    public void theAssociatedDataIsDefensivelyCopied() {
        final byte[] mutable = "v1;user=mark".getBytes(StandardCharsets.UTF_8);

        final ChaCha20Poly1305Encrypter cipher = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(MESSAGE)
                .setAssociatedData(mutable)
                .build();

        final byte[] original = mutable.clone();
        Arrays.fill(mutable, (byte) 'X');

        // The tag was computed over the value as it stood when the cipher was built.
        final byte[] decrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(cipher.encrypt())
                .setAssociatedData(original)
                .build()
                .decrypt();

        assertArrayEquals(MESSAGE, decrypted);
    }

    @Test
    public void theCiphertextDoesNotContainThePlaintext() {
        final byte[] secret = "a very recognizable secret".getBytes(StandardCharsets.UTF_8);

        final byte[] encrypted = encrypt(secret);

        final String asLatin1 = new String(encrypted, StandardCharsets.ISO_8859_1);
        assertFalse(asLatin1.contains("recognizable"));
        assertTrue(asLatin1.length() > 0);
    }

    /**
     * ChaCha20 takes a 256 bit key and nothing else. The builder says so immediately rather
     * than letting it surface from {@code Cipher.init} at encrypt time.
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 15, 16, 24, 31, 33, 64})
    public void keyThatIsNot32BytesIsRejected(
            final int keyLengthBytes) {
        final ChaCha20Poly1305Encrypter.Builder builder = new ChaCha20Poly1305Encrypter.Builder();
        final SecretKey wrongSize = new SecretKeySpec(new byte[keyLengthBytes],
                SecretKeys.CHACHA20_KEY_ALGORITHM);

        final IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> builder.setSecretKey(wrongSize));
        assertTrue(e.getMessage().contains("exactly 32 bytes"),
                "unexpected message: " + e.getMessage());
    }

    @Test
    public void nullArgumentsThrow() {
        final ChaCha20Poly1305Encrypter.Builder builder = new ChaCha20Poly1305Encrypter.Builder();

        assertThrows(NullPointerException.class, () -> builder.setSecretKey(null));
        assertThrows(NullPointerException.class, () -> builder.setMessage(null));
        assertThrows(NullPointerException.class, () -> builder.setAssociatedData(null));
    }

    @Test
    public void buildWithoutAKeyOrMessageThrows() {
        final ChaCha20Poly1305Encrypter.Builder noKey = new ChaCha20Poly1305Encrypter.Builder()
                .setMessage(MESSAGE);
        assertThrows(NullPointerException.class, noKey::build);

        final ChaCha20Poly1305Encrypter.Builder noMessage = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY);
        assertThrows(NullPointerException.class, noMessage::build);
    }

    /**
     * The whole config-file workflow, for the cipher's own key type.
     */
    @Test
    public void keyFromSecretKeysRoundTripsThroughConfiguration() {
        final SecretKey generated = SecretKeys.randomChaCha20();
        assertEquals(ChaCha20Poly1305Encrypter.KEY_LENGTH_BYTES, generated.getEncoded().length);
        assertEquals(SecretKeys.CHACHA20_KEY_ALGORITHM, generated.getAlgorithm());

        final String asConfigValue = SecretKeys.toBase64(generated);
        final String algorithm = SecretKeys.CHACHA20_KEY_ALGORITHM;

        final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(SecretKeys.fromBase64(asConfigValue, algorithm))
                .setMessage(MESSAGE)
                .build()
                .encrypt();

        // A separate read of the same config value, as a fresh process would do.
        final byte[] decrypted = new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(SecretKeys.fromBase64(asConfigValue, algorithm))
                .setMessage(encrypted)
                .build()
                .decrypt();

        assertArrayEquals(MESSAGE, decrypted);
    }

    private static byte[] encrypt(
            final byte[] message) {
        return new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(message)
                .build()
                .encrypt();
    }

    @Nullable
    private static byte[] decrypt(
            final byte[] payload) {
        return new ChaCha20Poly1305Encrypter.Builder()
                .setSecretKey(KEY)
                .setMessage(payload)
                .build()
                .decrypt();
    }

    private static SecretKey generateKey() {
        try {
            final KeyGenerator generator =
                    KeyGenerator.getInstance(SecretKeys.CHACHA20_KEY_ALGORITHM);
            generator.init(256);
            return generator.generateKey();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("ChaCha20 key generation is unavailable.", e);
        }
    }

    private static byte[] hex(
            final String encoded) {
        final byte[] bytes = new byte[encoded.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(encoded.substring(i * 2, i * 2 + 2), 16);
        }

        return bytes;
    }

}
