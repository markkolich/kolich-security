# kolich-security

A small, framework-free signing, encryption and password hashing primitives library for Java.

> **Looking for runnable examples?** Every signer and encrypter has a working, end-to-end
> example under [`src/test/java/com/kolich/security/examples`](src/test/java/com/kolich/security/examples).
> The examples are ordinary JUnit tests, so they run with `mvn test` and cannot drift out of date.

## Introduction

Each class is built through a `Builder` (or is a static factory), and each is immutable once
built:

| Class | Package | What it does |
|---|---|---|
| `ByteSigner` | `com.kolich.security.sign` | Signs a `byte[]` with a key pair, embedding the signature and the message in one self-contained payload |
| `StringSigner` | `com.kolich.security.sign` | The same, over a `String`, returning URL-safe Base64 suitable for a cookie, query parameter or API key |
| `HmacSigner` | `com.kolich.security.sign` | HMAC signatures with a shared secret, with constant-time verification |
| `KeyDecoder` | `com.kolich.security.sign` | Reads an X.509 public key or a PKCS#8 private key out of Base64 or PEM text |
| `AESGaloisCounterEncrypter` | `com.kolich.security.encrypt` | Symmetric authenticated encryption with AES-GCM |
| `ChaCha20Poly1305Encrypter` | `com.kolich.security.encrypt` | The same, with the RFC 8439 ChaCha20-Poly1305 construction instead |
| `SecretKeys` | `com.kolich.security.encrypt` | Generates, renders and reads the symmetric keys the encrypters need |
| `PasswordEncrypter` | `com.kolich.security.encrypt` | Encrypts bytes with nothing but a password, in a self-describing payload |
| `PasswordHasher` | `com.kolich.security.hash` | Hashes and verifies passwords with bcrypt at a configurable cost factor |

### Which one do I want?

The three packages are genuinely different primitives, and picking the wrong one is the
easiest mistake to make here:

| | Hides the contents? | Reversible? | Key |
|---|---|---|---|
| **sign** — `ByteSigner`, `StringSigner` | **No** — the payload carries the message in the clear | Message is recoverable by anyone | Public/private pair |
| **sign** — `HmacSigner` | **No** — signature only, no message | n/a | One shared secret |
| **encrypt** | **Yes** | Yes, with the key | One shared secret |
| **hash** | n/a | No | None |

Signing proves who wrote a message and that nobody changed it. It does **not** conceal it: a
signed session cookie can be read by anyone who Base64-decodes it, which is what makes
`extract()` possible at all. Reach for `encrypt` when the contents themselves should not be
readable by the party holding the payload.

Choose between the two signing styles by asking whether the verifying party should also be
able to *mint* signatures. With `HmacSigner` it can, because there is only one secret; with
`ByteSigner`/`StringSigner` it cannot, because verifying needs only the public key.

There is no dependency injection, no configuration object, and no web framework in here. Keys
are handed to the builder; nothing in this library reads a config file, a system property or
the environment.

`sign` and `encrypt` depend on nothing but the JDK. `PasswordHasher` needs
[jbcrypt](https://github.com/jeremyh/jBCrypt), which is declared `optional` so that it does not
land on your classpath unless you use that class.

## Latest Version

See the [Releases page](https://github.com/markkolich/kolich-security/releases) to find the
latest version.

## Resolving

```xml
<repositories>
    <repository>
        <id>markkolich.github.io</id>
        <name>markkolich.github.io</name>
        <url>https://markkolich.github.io/repo</url>
        <releases />
        <snapshots>
            <enabled>false</enabled>
        </snapshots>
    </repository>
</repositories>
```

```xml
<dependency>
    <groupId>com.kolich</groupId>
    <artifactId>kolich-security</artifactId>
    <version>1.0</version>
</dependency>
```

If you use `PasswordHasher`, declare jbcrypt yourself:

```xml
<dependency>
    <groupId>org.mindrot</groupId>
    <artifactId>jbcrypt</artifactId>
    <version>0.4</version>
</dependency>
```

## Generating the key material

Before any of this is useful you need keys. Both of these produce exactly what the library
reads.

**An RSA key pair, for `ByteSigner` and `StringSigner`:**

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
```

`genpkey` writes PKCS#8 (`-----BEGIN PRIVATE KEY-----`) and `rsa -pubout` writes X.509
(`-----BEGIN PUBLIC KEY-----`), which is what `KeyDecoder` expects. You can paste either file
into a config value verbatim — armor, line breaks and all — or strip it to one line first;
both read.

**A symmetric key, for `AESGaloisCounterEncrypter` or `ChaCha20Poly1305Encrypter`:**

```bash
openssl rand -base64 32
```

Thirty-two bytes is a 256 bit AES key and is also exactly the size RFC 8439 fixes for a
ChaCha20 key, so that one command covers either encrypter. Or from Java, which avoids a shell
round trip and names which encrypter the key is for:

```java
// for AESGaloisCounterEncrypter
System.out.println(SecretKeys.toBase64(SecretKeys.random()));

// for ChaCha20Poly1305Encrypter
System.out.println(SecretKeys.toBase64(SecretKeys.randomChaCha20()));
```

Either way the output is one Base64 line to paste into a config value, which
`SecretKeys.fromBase64(...)` reads back at startup. See
[Getting a key for the encrypters](#getting-a-key-for-the-encrypters) for the read-back side
and why a key belongs to one encrypter.

## Usage

### StringSigner

Build it once and reuse it; it is immutable and thread safe.

```java
final StringSigner signer = new StringSigner.Builder()
        .setPublicKey(config.getString("signer-public-key"))
        .setPrivateKey(config.getString("signer-private-key"))
        .build();

final String token = signer.sign("user=mark;expires=1793308800");
// -> "AAABAHru7aN9QF9dU3DpOZ2cZIHDkBkJKh-WmGfbIzqJ-kbs..."

final String verified = signer.verifyAndGet(token);
// -> "user=mark;expires=1793308800", or null if the token does not verify
```

The string overloads above go through `KeyDecoder`, for the common case of a key pair living
in a configuration file. Pass `PublicKey`/`PrivateKey` objects instead if you already have
them.

`verifyAndGet` returns `null` for anything that is not a token this signer issued — tampered,
truncated, signed by another key, or not even valid Base64. That is the whole check:

```java
final String payload = signer.verifyAndGet(cookieValue);
if (payload == null) {
    throw new ForbiddenException("Bad session cookie.");
}
```

A signer given only a public key can verify but not sign, which is the right shape for a
service that validates tokens it does not issue:

```java
final StringSigner verifyOnly = new StringSigner.Builder()
        .setPublicKey(config.getString("signer-public-key"))
        .build();

verifyOnly.verifyAndGet(token);   // fine
verifyOnly.sign("nope");          // throws NullPointerException
```

One given only a private key can sign but not verify. `SHA512withRSA` is the default;
`setAlgorithm(ByteSigner.Algorithm.SHA256_WITH_RSA)` selects the other.

### ByteSigner

Same scheme over raw bytes. A `ByteSigner` holds one message, so build a new one per message.

```java
final PrivateKey privateKey = KeyDecoder.privateKey(config.getString("signer-private-key"));
final PublicKey publicKey = KeyDecoder.publicKey(config.getString("signer-public-key"));

final byte[] payload = new ByteSigner.Builder()
        .setAlgorithm(ByteSigner.Algorithm.SHA256_WITH_RSA)
        .setPrivateKey(privateKey)
        .setMessage(message)
        .build()
        .sign();

final byte[] original = new ByteSigner.Builder()
        .setAlgorithm(ByteSigner.Algorithm.SHA256_WITH_RSA)
        .setPublicKey(publicKey)
        .setMessage(payload)
        .build()
        .extract();   // null if the payload does not verify
```

Use `verify()` instead of `extract()` when you only need the yes/no and not the body back.

### HmacSigner

For a shared-secret scheme: verifying a third party's webhook, or signing API requests in the
style of AWS Signature V2.

```java
// The string to sign is whatever the scheme says it is; this shape is Mailgun's.
final String stringToSign = timestamp + token;

final HmacSigner hmac = new HmacSigner.Builder()
        .setAlgorithm(HmacSigner.Algorithm.HMAC_SHA256)
        .setEncoding(HmacSigner.Encoding.HEX)
        .setSecret(config.getString("webhook-signing-secret"))
        .setMessage(stringToSign)
        .build();

if (!hmac.verify(signatureFromTheRequest)) {
    throw new ForbiddenException("Signature verification failed.");
}
```

**Always check with `verify(...)` rather than comparing `sign()` yourself:**

```java
// WRONG - String.equals returns at the first differing byte, so the time it takes
// leaks how much of a forged signature was correct.
if (!signatureFromTheRequest.equals(hmac.sign())) { ... }

// RIGHT - compares through MessageDigest.isEqual, which does not short circuit.
if (!hmac.verify(signatureFromTheRequest)) { ... }
```

`verify` returns `false` rather than throwing for a signature that is not even well-formed in
the configured encoding, so hostile input needs no special handling. Hex is compared
case-insensitively. `verify(byte[])` takes a raw signature if you have one, and
`signToBytes()` gives you the unencoded MAC.

To *issue* signatures rather than check them, `sign()` returns the encoded string:

```java
final String authorization = String.format("MyScheme %s:%s", accessKey, hmac.sign());
```

`HMAC_SHA256` and `BASE64` are the defaults. HMAC-SHA1 is still sound — HMAC does not rely on
the collision resistance that makes bare SHA-1 unfit for signatures — and is there for
compatibility with existing schemes; prefer SHA-256 for anything new.

### KeyDecoder

```java
final PublicKey publicKey = KeyDecoder.publicKey(config.getString("signer-public-key"));
final PrivateKey privateKey = KeyDecoder.privateKey(config.getString("signer-private-key"));

// A non-RSA key pair needs its algorithm naming:
final PublicKey ecKey = KeyDecoder.publicKey(encodedEcKey, "EC");
```

A public key is read as X.509 `SubjectPublicKeyInfo` and a private key as PKCS#8
`PrivateKeyInfo`, which is what `Key.getEncoded()` produces and what `openssl` writes by
default. The Base64 is read leniently, because a key copied out of a `.pem` file picks up line
breaks and armor along the way: PEM `-----BEGIN ...-----` lines are stripped, whitespace is
ignored, and both the standard (`+ /`) and URL-safe (`- _`) alphabets are accepted. All of
these read, and the first three give the same key:

```java
// a whole PEM file, armor and line breaks included
KeyDecoder.publicKey(new String(Files.readAllBytes(Paths.get("public.pem"))));

// the same key as one line, standard alphabet
KeyDecoder.publicKey("MIIBIjANBgkq...r+Ck/9Qm2w==");

// the same key as one line, URL-safe alphabet
KeyDecoder.publicKey("MIIBIjANBgkq...r-Ck_9Qm2w==");
```

A character belonging to neither alphabet still fails, so genuine corruption is not silently
skipped. Failure is a `SignerException`, since an unreadable key is a configuration fault:

```java
try {
    return KeyDecoder.privateKey(config.getString("signer-private-key"));
} catch (final SignerException e) {
    throw new IllegalStateException("signer-private-key is not a usable key", e);
}
```

### AESGaloisCounterEncrypter

```java
// Once, offline, to produce the value that goes in the config file.
System.out.println(SecretKeys.toBase64(SecretKeys.random()));   // 256 bit AES key

// At startup, reading that value back.
final SecretKey key = SecretKeys.fromBase64(config.getString("encrypt-key"));

final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
        .setSecretKey(key)
        .setMessage(plaintext)
        .build()
        .encrypt();

final byte[] original = new AESGaloisCounterEncrypter.Builder()
        .setSecretKey(key)
        .setMessage(encrypted)
        .build()
        .decrypt();   // null if the payload does not authenticate
```

`encrypt()` draws a fresh random IV on every call and prepends it to the output:

```
[ iv ][ ciphertext || authentication tag ]
```

**An IV must never be reused with the same key.** GCM fails catastrophically on nonce reuse:
two messages under the same key and IV leak their XOR, and recovering the authentication
subkey becomes possible, which lets an attacker forge messages. This class therefore does not
accept an IV from the caller at all.

`setAssociatedData(...)` adds data that is authenticated but not encrypted, which binds a
ciphertext to a context so it cannot be replayed into a different one. It must be supplied
identically to decrypt, or decryption returns `null`:

```java
final byte[] encrypted = new AESGaloisCounterEncrypter.Builder()
        .setSecretKey(key)
        .setMessage(plaintext)
        .setAssociatedData(("session:v1:" + userId).getBytes(UTF_8))
        .build()
        .encrypt();

// Decrypting with different associated data returns null, even with the right key.
final byte[] original = new AESGaloisCounterEncrypter.Builder()
        .setSecretKey(key)
        .setMessage(encrypted)
        .setAssociatedData(("session:v1:" + userId).getBytes(UTF_8))
        .build()
        .decrypt();
```

A `null` return covers every failure — tampered, truncated, wrong key, wrong associated data.
GCM cannot tell them apart and neither can you, which is the point: a failed decryption
reveals nothing about why it failed.

The default IV length is **12 bytes**, which is what NIST SP 800-38D specifies, and the default
tag length is the full 128 bits. `setIvLengthBytes(...)` exists only so that data written with
a different length can still be read; new data should use the default.

### ChaCha20Poly1305Encrypter

The same API, over the RFC 8439 construction — the ChaCha20 stream cipher for
confidentiality, the Poly1305 one-time authenticator for integrity:

```java
// Once, offline, to produce the value that goes in the config file.
System.out.println(SecretKeys.toBase64(SecretKeys.randomChaCha20()));   // always 256 bit

// At startup, naming the algorithm so the 32 byte length is checked on the way in.
final SecretKey key = SecretKeys.fromBase64(
        config.getString("encrypt-key"), SecretKeys.CHACHA20_KEY_ALGORITHM);

final byte[] encrypted = new ChaCha20Poly1305Encrypter.Builder()
        .setSecretKey(key)
        .setMessage(plaintext)
        .build()
        .encrypt();

final byte[] original = new ChaCha20Poly1305Encrypter.Builder()
        .setSecretKey(key)
        .setMessage(encrypted)
        .build()
        .decrypt();   // null if the payload does not authenticate
```

`setAssociatedData(...)` behaves exactly as it does on the AES cipher, and a `null` return
covers every failure the same way.

Nothing about the lengths is configurable, because RFC 8439 fixes all of them: the nonce is
always 12 bytes, the tag always 16, the key always 32. `encrypt()` draws a fresh random nonce
per call and prepends it:

```
[ nonce ][ ciphertext || authentication tag ]
```

**That is the same layout, at the same lengths, that `AESGaloisCounterEncrypter` writes at its
defaults — and the payloads are still not interchangeable.** Handing one class the other's
output returns `null`, like any other ciphertext it cannot authenticate, and nothing in the
payload records which cipher wrote it. If you may hold data from both, keep that distinction
yourself; a version byte in the associated data is one way to do it.

#### Which of the two encrypters should I use?

Either. Both are sound, neither is broken, and the choice rarely matters. The arguments for
ChaCha20-Poly1305:

- It is built from addition, rotation and exclusive-or on a fixed schedule, with no lookup
  tables, so it runs in constant time on every machine. AES without the AES-NI instruction
  falls back to key-dependent table lookups, and that is a timing side channel.
- Nonce reuse, while still a serious failure, is a contained one. The Poly1305 one-time key is
  derived from the key *and* the nonce, so a repeat permits forgery under that one nonce. GCM's
  authentication subkey does not depend on the nonce at all, so recovering it once permits
  forgery under every nonce.
- It is the default in TLS 1.3, WireGuard and SSH, so it is a well-exercised path.

The argument for AES-GCM is speed on hardware that has AES-NI — which is most hardware this is
likely to run on — where the HotSpot intrinsic makes AES-GCM the faster of the two by some
margin.

What does matter is not changing your mind after writing data.

### Getting a key for the encrypters

Two ways, and the first is usually the better one.

**A stored random key.** Generate once, keep the Base64 in configuration:

```java
// once, to produce the value that goes in the config file
System.out.println(SecretKeys.toBase64(SecretKeys.random()));

// at startup
final SecretKey key = SecretKeys.fromBase64(config.getString("encrypt-key"));
```

`fromBase64` ignores whitespace and takes either alphabet, and it checks that an AES key
decoded to 16, 24 or 32 bytes — a truncated or mistyped value fails here with a clear message
rather than much later inside `Cipher.init`.

For `ChaCha20Poly1305Encrypter`, whose key is always 256 bits, generate with `randomChaCha20()`
and name the algorithm when reading it back, which checks for exactly 32 bytes:

```java
// once, to produce the value that goes in the config file
System.out.println(SecretKeys.toBase64(SecretKeys.randomChaCha20()));

// at startup
final SecretKey key = SecretKeys.fromBase64(
        config.getString("encrypt-key"), SecretKeys.CHACHA20_KEY_ALGORITHM);
```

A ChaCha20 key and a 256 bit AES key are both 32 random bytes, so nothing stops one being
handed to the other cipher. Don't: a key belongs to one cipher. Reusing key material across
two constructions buys nothing and forfeits the independence that makes keeping a second
cipher around worthwhile in the first place.

**A password instead of a key.** When the secret is a passphrase somebody types rather than a
key you store, use `PasswordEncrypter` below. It derives a key per payload and records the
parameters alongside the ciphertext, so there is no key to keep and no salt to manage.

A stored random key has the full entropy of its length rather than whatever a chosen
passphrase happens to carry, and costs nothing per operation, so prefer it for anything on a
hot path. The key is only as protected as the file it sits in, though: it is key material in
plain text, so treat the file accordingly.

### PasswordEncrypter

When the secret is a passphrase rather than a key, this encrypts bytes with the password alone
and hands back a payload that carries everything needed to open it again except the password:

```java
final byte[] encrypted = new PasswordEncrypter.Builder()
        .setPassword(passphrase)
        .setMessage(fileBytes)
        .build()
        .encrypt();

final byte[] original = new PasswordEncrypter.Builder()
        .setPassword(passphrase)
        .setMessage(encrypted)
        .build()
        .decrypt();   // null if the password is wrong or the payload is damaged
```

The payload is laid out as:

```
[ version ][ kdf id ][ iterations ][ salt len ][ salt ][ iv len ][ iv ][ ciphertext || tag ]
```

**The salt and iteration count live in the payload, not in configuration**, and that header is
authenticated as the cipher's associated data so it cannot be altered in transit. This is the
whole point of the class: `decrypt()` reads the parameters out of the payload it was given and
ignores whatever the builder was told, so raising the iteration count affects new output only
and everything already encrypted still opens.

```java
// Written years ago with cheap parameters and a different algorithm...
final byte[] old = new PasswordEncrypter.Builder()
        .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA1)
        .setPassword(passphrase)
        .setMessage(message)
        .setIterationCount(1_000)
        .build()
        .encrypt();

// ...still opens under today's much stricter settings.
final byte[] recovered = new PasswordEncrypter.Builder()
        .setAlgorithm(PasswordEncrypter.Algorithm.PBKDF2_WITH_HMAC_SHA512)
        .setPassword(passphrase)
        .setMessage(old)
        .setIterationCount(500_000)
        .build()
        .decrypt();
```

Key derivation is deliberately expensive, and because every payload has its own salt that cost
is paid on **every** `encrypt()` and `decrypt()` call — measured at a little over 100ms at the
default of 210,000 iterations. That makes this right for occasional work: a file, an export, a
backup, anything guarded by a typed passphrase. It is the wrong tool for a per-request path
like a session cookie; store a random key with `SecretKeys` and use `AESGaloisCounterEncrypter`
directly for that, which costs nothing per operation.

A `null` return covers every failure, indistinguishably: wrong password, tampered or truncated
payload, unrecognised version or algorithm, nonsensical lengths. An iteration count above
`MAX_ITERATION_COUNT` is also rejected, since that number is attacker controlled and its whole
purpose is to cost work — obeying a payload that demands two billion iterations would be a
denial of service against whoever opened it.

### PasswordHasher

```java
final PasswordHasher hasher = new PasswordHasher.Builder()
        .setRounds(12)   // the default; 4..30 permitted
        .build();

final String hash = hasher.hash(password);
// -> "$2a$12$Ht0E2vJ0WqGmFUBPHRl0ieXtBtOvrsRB0bEqBJ2n5cRzMvJi1Nkk."

if (!hasher.verify(submittedPassword, storedHash)) {
    throw new ForbiddenException("Bad credentials.");
}
```

Verification reads the cost factor and salt out of the stored hash rather than from the
instance, so raising `setRounds` does not invalidate hashes already written at a lower cost:

```java
final PasswordHasher stronger = new PasswordHasher.Builder().setRounds(14).build();
stronger.verify(password, aHashWrittenAtTwelveRounds);   // still true
```

Hashing is salted, so the same password hashed twice gives different output. Never compare
hashes to each other; always go through `verify`.

## Signature payload format

`ByteSigner.sign()` produces a length-prefixed signature followed by the message body:

```
[ 4-byte big-endian signature length ][ signature ][ message ]
```

`StringSigner` wraps that in `Base64.getUrlEncoder()`.

Prefixing the signature with its own length is what keeps the format independent of the key
size. An RSA signature is exactly as long as the modulus, so a signer that instead assumes a
fixed signature length works at 2048 bits and then silently stops verifying anything the day
the key is rotated to 4096. `ByteSignerTest` asserts the round trip at 1024, 2048, 3072 and
4096 bits to keep that property nailed down.

The signature length is read out of caller-supplied bytes before it is used as an offset, so
it is range checked first. A payload that is too short, declares a nonsensical length, carries
a malformed signature, or simply does not verify is reported as `false` from `verify()` and
`null` from `extract()`. None of those is an exception: an invalid token is an expected input,
not an error.

## Errors

The two exception types are for configuration and environment faults only — an algorithm the
JVM does not provide, a key that is unusable, a key that was never supplied:

| | Thrown by |
|---|---|
| `SignerException` | `com.kolich.security.sign` |
| `CipherException` | `com.kolich.security.encrypt` |

Both are unchecked, and neither ever carries the value being signed, verified or encrypted in
its message, so they are safe to log.

Invalid *input* is not an error and is never thrown: `verify()` returns `false` and
`verifyAndGet()`, `extract()` and `decrypt()` return `null`. A missing key is a programming
error and throws `NullPointerException`.

## No logging

This library has no logger and no logging dependency, on purpose. The values that flow through
a signer or a cipher are session payloads, tokens, API keys and plaintext, and a library has no
business deciding whether such a value may be written to a log file. What to do about a `null`
return or a `false` is the caller's policy to set.

## Compiling

Requires Java 11 or later, and is packaged using Maven.

```
mvn clean package
```

The resulting JAR, sources JAR and POM, each with `.md5` and `.sha1` sidecars, are written to
the local `dist` directory, laid out the way a Maven repository expects.

Correctness is checked against published test vectors where they exist: RFC 2202 and RFC 4231
for HMAC, and RFC 6070 for PBKDF2.

## License

Copyright (c) 2026 <a href="https://mark.koli.ch">Mark S. Kolich</a>

All code in this project is freely available for use and redistribution under the <a href="http://opensource.org/comment/991">MIT License</a>.

See <a href="https://github.com/markkolich/kolich-security/blob/master/LICENSE">LICENSE</a> for details.
