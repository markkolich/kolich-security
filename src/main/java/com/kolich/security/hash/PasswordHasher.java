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

import org.mindrot.jbcrypt.BCrypt;

import javax.annotation.Nonnull;
import java.util.Objects;

/**
 * Hashes and verifies passwords with bcrypt, using a configurable cost factor.
 *
 * <p>The cost factor is a base-2 logarithm: each increment doubles the work needed to
 * compute a hash. It is set once on the {@link Builder} and applies to every hash the
 * resulting instance produces.
 *
 * <p>Verification does not use the configured cost factor at all. A bcrypt hash records
 * the cost factor that produced it, so {@link #verify(String, String)} will correctly
 * check a hash written by an instance configured differently, which is what makes it
 * possible to raise the cost factor without invalidating the hashes already stored.
 *
 * <p>Instances are immutable and thread safe.
 *
 * <p><strong>bcrypt reads at most the first 72 bytes of a password and silently ignores the
 * rest.</strong> Any two passwords sharing a 72 byte prefix are therefore the same password
 * as far as {@link #verify(String, String)} is concerned. That is bcrypt's own design rather
 * than a choice made here, and it is not worked around: pre-hashing the password first would
 * change what gets stored and invalidate every hash already written.
 *
 * <p>The limit counts <em>bytes of UTF-8</em>, not characters, so it arrives sooner than it
 * looks for anything outside ASCII — twenty-four three byte characters reach it. An
 * application that expects passphrases longer than that should hash them down to a fixed
 * length itself before calling, for instance Base64 of a SHA-512 digest, and should do so
 * from the outset, since introducing it later invalidates existing hashes just the same.
 *
 * <p>Unlike some bcrypt implementations, jbcrypt treats a NUL byte in a password as an
 * ordinary byte rather than a terminator. That only matters if hashes have to be portable to
 * another implementation.
 *
 * <p>This is the only class in this library that needs a third-party dependency. jbcrypt
 * is declared {@code optional} in the POM, so a consumer that uses this class has to
 * declare {@code org.mindrot:jbcrypt} itself.
 */
public final class PasswordHasher {

    /**
     * The cost factor used when the builder is not told otherwise.
     */
    public static final int DEFAULT_ROUNDS = 12;

    /**
     * The smallest cost factor bcrypt accepts.
     */
    public static final int MIN_ROUNDS = 4;

    /**
     * The largest cost factor bcrypt accepts. Note that a cost factor anywhere near this
     * is computationally absurd; it is here to bound the input, not to suggest a value.
     */
    public static final int MAX_ROUNDS = 30;

    private final int rounds_;

    private PasswordHasher(
            final int rounds) {
        rounds_ = rounds;
    }

    /**
     * Hashes the given password with a freshly generated random salt, at the cost factor
     * this instance was built with.
     *
     * <p>Only the first 72 bytes of the password contribute to the hash; see the class
     * documentation.
     */
    public String hash(
            @Nonnull final String password) {
        Objects.requireNonNull(password, "Password cannot be null.");

        return BCrypt.hashpw(password, BCrypt.gensalt(rounds_));
    }

    /**
     * Checks the given password against an existing bcrypt hash. The cost factor and salt
     * are read from the hash itself, not from this instance.
     *
     * <p>Only the first 72 bytes of the password are compared, so a password that merely
     * shares a 72 byte prefix with the real one is accepted; see the class documentation.
     *
     * @throws IllegalArgumentException if the hash is empty or is not a bcrypt hash
     */
    public boolean verify(
            @Nonnull final String password,
            @Nonnull final String hash) {
        Objects.requireNonNull(password, "Password cannot be null.");
        Objects.requireNonNull(hash, "Hash cannot be null.");
        if (hash.isEmpty()) {
            throw new IllegalArgumentException("Hash cannot be empty.");
        }

        return BCrypt.checkpw(password, hash);
    }

    public static final class Builder {

        private int rounds_ = DEFAULT_ROUNDS;

        /**
         * Sets the bcrypt cost factor, which must be between {@link #MIN_ROUNDS} and
         * {@link #MAX_ROUNDS} inclusive.
         */
        public Builder setRounds(
                final int rounds) {
            if (rounds < MIN_ROUNDS || rounds > MAX_ROUNDS) {
                throw new IllegalArgumentException("Rounds must be between " + MIN_ROUNDS
                        + " and " + MAX_ROUNDS + " inclusive, but was: " + rounds);
            }
            rounds_ = rounds;
            return this;
        }

        public PasswordHasher build() {
            return new PasswordHasher(rounds_);
        }

    }

}
