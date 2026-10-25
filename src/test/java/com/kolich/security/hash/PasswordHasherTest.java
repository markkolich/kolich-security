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

package com.kolich.security.hash;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class PasswordHasherTest {

    /**
     * Every test here hashes at the minimum cost factor. bcrypt is deliberately slow and
     * the cost factor is a base-2 logarithm, so hashing at the production default would
     * make this suite hundreds of times slower while testing nothing extra.
     */
    private static final PasswordHasher HASHER = new PasswordHasher.Builder()
            .setRounds(PasswordHasher.MIN_ROUNDS)
            .build();

    /**
     * A character that occupies three bytes in UTF-8, used to show that bcrypt's limit is
     * counted in bytes rather than in characters.
     */
    private static final char THREE_BYTE_CHAR = '\u4f60'; // CJK; three bytes in UTF-8

    @ParameterizedTest
    @ValueSource(strings = {
        "correct horse battery staple",
        "p",
        "",
        "éèê unicode 你好",
        "   spaces   ",
        "$2a$04$notActuallyAHashJustALookalike"
    })
    public void hashThenVerifyRoundTrip(
            final String password) {
        final String hash = HASHER.hash(password);

        assertTrue(HASHER.verify(password, hash));
    }

    @Test
    public void wrongPasswordDoesNotVerify() {
        final String hash = HASHER.hash("the right one");

        assertFalse(HASHER.verify("the wrong one", hash));
        assertFalse(HASHER.verify("", hash));
        assertFalse(HASHER.verify("The Right One", hash));
    }

    /**
     * bcrypt salts every hash, so the same password hashed twice must not produce the same
     * output. Identical hashes would mean the salt was not random.
     */
    @Test
    public void hashingIsSaltedAndSoIsNotDeterministic() {
        final String first = HASHER.hash("same password");
        final String second = HASHER.hash("same password");

        assertNotEquals(first, second);
        assertTrue(HASHER.verify("same password", first));
        assertTrue(HASHER.verify("same password", second));
    }

    /**
     * A hash records the cost factor that produced it, so raising the cost factor must not
     * invalidate hashes already written at a lower one.
     */
    @Test
    public void verifiesAHashWrittenAtADifferentCostFactor() {
        final PasswordHasher cheap = new PasswordHasher.Builder()
                .setRounds(4)
                .build();
        final PasswordHasher dearer = new PasswordHasher.Builder()
                .setRounds(6)
                .build();

        final String cheapHash = cheap.hash("portable");
        final String dearerHash = dearer.hash("portable");

        assertNotEquals(cheapHash, dearerHash);

        // Either instance verifies either hash.
        assertTrue(cheap.verify("portable", dearerHash));
        assertTrue(dearer.verify("portable", cheapHash));
    }

    @Test
    public void theCostFactorIsRecordedInTheHash() {
        final String hash = new PasswordHasher.Builder()
                .setRounds(5)
                .build()
                .hash("cost factor check");

        assertTrue(hash.startsWith("$2a$05$"), "unexpected hash prefix: " + hash.substring(0, 7));
    }

    @ParameterizedTest
    @ValueSource(ints = {3, 2, 1, 0, -1, Integer.MIN_VALUE, 31, 100, Integer.MAX_VALUE})
    public void anOutOfRangeCostFactorIsRejected(
            final int rounds) {
        final PasswordHasher.Builder builder = new PasswordHasher.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.setRounds(rounds));
    }

    @ParameterizedTest
    @ValueSource(ints = {PasswordHasher.MIN_ROUNDS, 5, 6})
    public void anInRangeCostFactorIsAccepted(
            final int rounds) {
        final PasswordHasher hasher = new PasswordHasher.Builder()
                .setRounds(rounds)
                .build();

        assertTrue(hasher.verify("accepted", hasher.hash("accepted")));
    }

    @Test
    public void costFactorConstantsAreStable() {
        assertEquals(12, PasswordHasher.DEFAULT_ROUNDS);
        assertEquals(4, PasswordHasher.MIN_ROUNDS);
        assertEquals(30, PasswordHasher.MAX_ROUNDS);
    }

    /**
     * A builder that is never told a cost factor hashes at {@link
     * PasswordHasher#DEFAULT_ROUNDS}. This is the one test that pays the full production
     * cost of a hash, which is the point of it.
     */
    @Test
    public void theDefaultCostFactorIsUsedWhenNoneIsSet() {
        final PasswordHasher hasher = new PasswordHasher.Builder().build();

        final String hash = hasher.hash("default rounds");

        assertTrue(hash.startsWith("$2a$12$"), "unexpected hash prefix: " + hash.substring(0, 7));
        assertTrue(hasher.verify("default rounds", hash));
    }

    /**
     * Pins bcrypt's 72 byte password limit, so that the documented behaviour is also the
     * tested behaviour and a future change to it cannot pass unnoticed. The boundary is
     * exact: 71 bytes plus a character is a different password, 72 bytes plus a character
     * is not.
     */
    @Test
    public void onlyTheFirstSeventyTwoBytesOfAPasswordAreUsed() {
        final String seventyOne = repeat('a', 71);
        final String seventyTwo = repeat('a', 72);

        assertFalse(HASHER.verify(seventyOne + "X", HASHER.hash(seventyOne)),
                "71 bytes should not be truncated");

        assertTrue(HASHER.verify(seventyTwo + "X", HASHER.hash(seventyTwo)),
                "beyond 72 bytes should be ignored");
        assertTrue(HASHER.verify(seventyTwo + "A-MUCH-LONGER-TAIL",
                HASHER.hash(seventyTwo)));
        // ...and symmetrically, a hash of the long form accepts the short one.
        assertTrue(HASHER.verify(seventyTwo, HASHER.hash(seventyTwo + "A-MUCH-LONGER-TAIL")));
    }

    /**
     * The limit counts bytes of UTF-8 rather than characters, so it arrives after only
     * twenty-four three byte characters.
     */
    @Test
    public void theSeventyTwoByteLimitCountsBytesNotCharacters() {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 24; i++) {
            sb.append(THREE_BYTE_CHAR);
        }
        final String twentyFourChars = sb.toString();

        assertEquals(72, twentyFourChars.getBytes(StandardCharsets.UTF_8).length);
        assertEquals(24, twentyFourChars.length());

        assertTrue(HASHER.verify(twentyFourChars + THREE_BYTE_CHAR,
                HASHER.hash(twentyFourChars)));
    }

    /**
     * jbcrypt treats a NUL byte as an ordinary byte rather than a terminator, unlike some
     * other bcrypt implementations. Asserted because the opposite is widely assumed.
     */
    @Test
    public void nulByteDoesNotTerminateThePassword() {
        final String hash = HASHER.hash("abc\u0000SECRET-TAIL");

        assertFalse(HASHER.verify("abc", hash));
        assertFalse(HASHER.verify("abc\u0000DIFFERENT", hash));
        assertTrue(HASHER.verify("abc\u0000SECRET-TAIL", hash));
    }

    @Test
    public void nullArgumentsThrow() {
        final String hash = HASHER.hash("something");

        assertThrows(NullPointerException.class, () -> HASHER.hash(null));
        assertThrows(NullPointerException.class, () -> HASHER.verify(null, hash));
        assertThrows(NullPointerException.class, () -> HASHER.verify("something", null));
    }

    @Test
    public void anEmptyHashIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> HASHER.verify("something", ""));
    }

    @Test
    public void malformedHashIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> HASHER.verify("something", "not-a-bcrypt-hash"));
    }

    private static String repeat(
            final char ch,
            final int times) {
        final StringBuilder sb = new StringBuilder(times);
        for (int i = 0; i < times; i++) {
            sb.append(ch);
        }

        return sb.toString();
    }

}
