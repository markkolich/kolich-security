# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

kolich-security is a small, standalone library of signing, encryption and password hashing
primitives. It is deliberately framework-free: no dependency injection, no configuration
object, no web framework, no logger. Keys are passed in on each class's `Builder`.

It is published to `https://markkolich.github.io/repo` as `com.kolich:kolich-security`, the
same channel as [curacao](https://github.com/markkolich/curacao).

## Build Commands

```bash
# Compile, test, run checkstyle + PMD + duplicate-finder, package, and stage into dist/
mvn clean package

# Tests only
mvn test

# Check for dependency and plugin updates
mvn versions:display-dependency-updates
mvn versions:display-plugin-updates
```

`mvn package` writes the JAR, sources JAR and POM into `dist/kolich-security/<version>/`,
each with `.md5` and `.sha1` sidecars, laid out the way a Maven repository expects. Publishing
means copying that directory into the `markkolich.github.io/repo` checkout.

This is a **single-module** project whose parent is `com.kolich:kolich-parent`
(`~/workspace/kolich-parent`), like Mark's other projects. The parent versions the libraries
shared across them (here jbcrypt and the JUnit BOM; only `jsr305` is versioned locally) and
configures Checkstyle, PMD, duplicate-finder and versions-maven-plugin from the
`kolich-build-config` JAR on each plugin's classpath; there is no local `build/` directory.
The parent targets Java 21, so this POM sets `project.java-release.version` to 11, which the
compiler and the parent's PMD `targetJdk` both read. Because Maven resolves plugin dependencies
only from `<pluginRepositories>`, the github.io repo is declared there as well as under
`<repositories>`; without it the build works only when `kolich-build-config` is already in `~/.m2`.
A consumer resolving this library also fetches `kolich-parent`'s POM from the same repo.

## Package Structure

Three packages, one per primitive, because choosing the wrong primitive is the easy mistake:

- **`com.kolich.security.sign`** — `ByteSigner`, `StringSigner`, `HmacSigner`, `KeyDecoder`
- **`com.kolich.security.encrypt`** — `AESGaloisCounterEncrypter`, `ChaCha20Poly1305Encrypter`,
  `SecretKeys`, `PasswordEncrypter`
- **`com.kolich.security.hash`** — `PasswordHasher`
- **`com.kolich.security.exceptions`** — `SignerException`, `CipherException`

Signing gives integrity and authenticity but **no confidentiality** — a signed payload carries
its message in the clear, which is what makes `extract()` possible. Encryption gives both.
Keep that distinction straight in any new documentation or Javadoc.

## Dependencies

- `sign` and `encrypt` are **pure JDK**. Keep them that way; adding a dependency to either
  package is a decision, not a convenience.
- `jsr305` is `provided` scope, for `@Nullable`/`@Nonnull` at compile time only. Consumers do
  not inherit it.
- `jbcrypt` is `optional`, needed only by `PasswordHasher`. A consumer that uses that class
  declares jbcrypt itself. This is verified behaviour: running the signers and cipher with only
  this JAR on the classpath works, and only `PasswordHasher` throws `NoClassDefFoundError`.

## Design Conventions

These are load-bearing. Breaking one is an API change, not a refactor.

### Invalid input is reported, not thrown

An attacker-supplied payload that is too short, declares a nonsensical length, is malformed
Base64, or simply does not authenticate is an **expected input**, not an error:

- `verify()` returns `false`
- `verifyAndGet()`, `extract()`, `decrypt()` return `null`

`SignerException` and `CipherException` are reserved for configuration and environment faults
— an algorithm the JVM lacks, an unusable key. A missing key throws `NullPointerException`.

### No logging, ever

There is no logger and no logging dependency. The values flowing through these classes are
session payloads, tokens, API keys and plaintext, and a library has no business deciding
whether one may be written to a log file. An earlier copy of `StringSigner` elsewhere logged
the plaintext it was signing, which in one caller was raw API key material; having no logger
removes that failure mode by construction.

Exception messages must never contain the value being signed, verified or encrypted.

### Constant-time comparison for MACs

`HmacSigner.verify(...)` compares through `MessageDigest.isEqual`. Never compare MACs or
signatures with `String.equals` or `Arrays.equals` — those return at the first differing byte,
leaking via timing how much of a forged signature was correct. Verification belongs inside the
class so no call site can get it wrong.

### Defensive copies

Builders clone the `byte[]`/`char[]` they are given, and the constructors clone again where it
matters, so a caller cannot mutate a message out from under a signature already computed over
it. There are tests for this; keep them passing.

### Self-describing payload formats

`ByteSigner` length-prefixes the signature rather than assuming a fixed size, so the format
does not depend on the key size:

```
[ 4-byte big-endian signature length ][ signature ][ message ]
```

An implementation that assumes a fixed signature length verifies nothing at all once the key
is rotated past 2048 bits. `ByteSignerTest` pins the round trip at 1024/2048/3072/4096.

**This format is byte-identical to Onyx's current output**, verified by cross-signing between
the two implementations in both directions and under both algorithms. Changing it would
invalidate every token a deployed consumer has issued. Treat it as frozen.

Likewise `AESGaloisCounterEncrypter` prepends its IV, and the IV/tag lengths stay configurable
only so data written with other values can still be read.

`ChaCha20Poly1305Encrypter` writes `[ nonce ][ ciphertext || tag ]`, which at the AES cipher's
defaults is the *same layout at the same lengths* — 12 and 16 bytes. The payloads are not
interchangeable and nothing in them records which cipher wrote it. `ChaCha20Poly1305EncrypterTest`
pins that a mix-up fails closed in both directions, using identical raw key bytes on both sides
so the test is about the formats rather than the keys. **Do not add a discriminator byte to
either format** — that is a breaking change to `AESGaloisCounterEncrypter`, whose output is frozen.
A caller holding data from both encrypters distinguishes them itself.

Nothing in `ChaCha20Poly1305Encrypter` is configurable, because RFC 8439 fixes the nonce at 12
bytes, the tag at 16 and the key at 32. There is no truncated-tag variant and no legacy length
to read back, so there is no `setIvLengthBytes`/`setTagLengthBits` equivalent to add.

`PasswordEncrypter` goes further and writes its KDF parameters into the payload:

```
[ version ][ kdf id ][ iterations ][ salt len ][ salt ][ iv len ][ iv ][ ciphertext || tag ]
```

That header is passed to the cipher as associated data, so the parameters are authenticated
and cannot be altered in transit. Because they travel with the ciphertext, `decrypt()` ignores
whatever the builder was told and raising the default iteration count never orphans existing
data. **Do not move the salt or iteration count into configuration** — that is precisely the
arrangement this class exists to avoid, and it is why PBKDF2 is a private nested class rather
than public API.

The iteration count in a payload is attacker controlled and its purpose is to cost work, so
`decrypt()` rejects anything above `MAX_ITERATION_COUNT` before deriving. Removing that check
turns a payload into a denial of service against whoever opens it; there is a timed test
holding the line.

## Testing

JUnit 6, no Mockito — there is nothing worth mocking in a library this size. Tests run in
`America/Los_Angeles`.

**Use published test vectors wherever they exist.** Self-consistency tests pass even when the
inputs are fed to the algorithm wrongly, as long as they are fed wrongly in both directions:

- RFC 2202 and RFC 4231 for HMAC-SHA1/256/512
- RFC 6070 for PBKDF2-HMAC-SHA1
- RFC 8439 section 2.8.2 for ChaCha20-Poly1305, laid out in this library's own payload
  framing and pushed through the public API, so it pins the construction *and* the framing

Beyond the happy path, every class should cover: tampered input, truncated input, hostile
length fields, wrong key, malformed encodings, missing keys, and defensive copying.

Keep bcrypt and PBKDF2 tests at their **minimum** cost factor (`PasswordHasher.MIN_ROUNDS`, a
low iteration count). These functions are deliberately slow and the cost is exponential; one
test may pay the real production cost to prove the default, and no more.

## Code Style Requirements

Checkstyle, PMD and duplicate-finder all run at `prepare-package` and all fail the build. Their
configs live in `kolich-build-config` (in `~/workspace/kolich-parent`), shared by every project
on that parent — change them there, and only with reason.

- **Line length**: 120 characters max
- **Indentation**: 4 spaces, no tabs. `forceStrictCondition` is on with
  `lineWrappingIndentation=8`, so a continuation line is exactly +8 from the statement start,
  never progressively nested. Extract a local rather than fighting it.
- **Class member naming**: must end with an underscore (`algorithm_`)
- **Local variables**: at least 2 characters and the second character must be lowercase or a
  digit (`sigLength` is fine, `aByte` is not)
- **Method names**: same rule — the second character must be lowercase. This bites test names
  constantly: `aTamperedPayloadFails` is rejected, `tamperedPayloadFails` is fine. Do not start
  a method name with an article.
- **All non-exception classes must be `final`**
- **All method/constructor parameters must be `final`**
- **All local variables must be `final`**
- **Method and constructor arguments must start on a new line**, not on the signature line
- **License header required** on every `.java` file, matching
  `kolich/checkstyle/LICENSE.txt` in `kolich-build-config` byte for byte
- **No `@SuppressWarnings("PMD...")`** anywhere in this repo or curacao or Onyx. If PMD
  objects, change the code. `UseVarargs` on a trailing array parameter is satisfied with
  `char...`, which stays source-compatible with passing an array.
- `-Werror` with `-Xlint:all` is on, so a compiler warning fails the build too.

Checkstyle also validates `src/test/java`, so all of the above applies to tests.

## Git

This repository pins its own identity in `.git/config`:

```
user.name  = Mark Kolich
user.email = social@kolich.com
```

Do not edit `~/.gitconfig`, which intentionally holds a different default. Each repository
overrides it locally.

## Things That Are Deliberately Absent

Do not "fix" these without asking:

- No logger, no slf4j (see above)
- No Guava. `Objects.requireNonNull` replaces `checkNotNull`; this keeps `sign` and `encrypt`
  pure JDK
- No `KeyGenerator`/config/DI wrapper classes — wiring a key into an application is the
  application's job, which is exactly what keeps this library reusable
