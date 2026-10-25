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

package com.kolich.security.exceptions;

/**
 * Thrown when a signing or verification operation cannot be completed because of a
 * configuration or environment problem: an algorithm the JVM does not provide, a key
 * that is unusable with the chosen algorithm, or a key that was never supplied.
 *
 * <p>This exception does <em>not</em> indicate that a signature failed to verify. An
 * invalid, tampered, truncated or otherwise unverifiable payload is an expected outcome
 * rather than an error, and is reported as {@code false} or {@code null} by the signer
 * methods that check signatures.
 *
 * <p>Messages attached to this exception never include the plaintext being signed or the
 * payload being verified, so that the exception is safe for a caller to log.
 */
public final class SignerException extends RuntimeException {

    private static final long serialVersionUID = -8294163348113122132L;

    public SignerException(
            final String message,
            final Throwable cause) {
        super(message, cause);
    }

    public SignerException(
            final String message) {
        super(message);
    }

}
