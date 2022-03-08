## KmpCrypto

This is a Kotlin multiplatform (KMP) library for Cryptography, using the same API across all supported platforms.  Implementations are pure Kotlin, patterned on the BouncyCastle Java library. The platform-specific portions of the library, using expect/actual setup to leverage platform-specific implementations, are limited to:

- SecureRandom for random number generation

- [Bouncy Castle](https://www.bouncycastle.org/)

The library is early in its lifecycle so is missing lots of crypto functionality. If you want more, start a repo discussion! :-) 

Supported targets:

- Android X64 and Arm64 ABIs
- macosX64
- iosX64
- iosArm64
- jvm
- mingw64 currently not supported but is **easy** to add.
- linuxX64 currently not supported but is **easy** to add.

A common source set "appleNativeMain" contains common code used by all three Apple targets. 

## Reason for Existence

Kotlin multiplatform code needing basic cryptography functions should not need platform-specific code to do so. This library provides:

- Coroutine support using Dispatchers.IO
- Kotlin-friendly DSL syntax for configuring a Cryptography provider
- algorithms (engines)
  - AES
  - RC2
  - RC4
  - DES
  - 3DES
  - 3DES112
- modes usable on the above algorithms
  - CipherModes.None
  - CipherModes.CBC
  - CipherModes.CFB
  - CipherModes.CCM
  - CipherModes.GCM
  - CipherModes.ECB
- Padding 
  - None
  - PKCS5, PKCS7 (both do the same thing)
- Digests
  - None
  - SHA1
  - SHA256
  - SHA384
  - SHA512
  - MD5
  - MD4
  - MD2
  - RIPEMD128
  - RIPEMD160
  - Whirlpool
- Source/Sink lambdas - easy to consume any number of buffers from a Source, and produce any number of encrypted/decrypted bytes to a Sink. 

# Dependencies

Kotlin only is used for the KMP code. The kmp-io library that supports all the same targets is used for basic Charset support (used with String keys), ByteBuffer usage, and basic File IO
- Kotlin 1.6.10
- Kotlin atomicfu
- com.oldguy:kmp-io:0.1.1

## Notes

This library has been used extensively in one app, so has not so far been published to maven. It can be easily published to mavenLocal using the gradle "publishToMavenLocal" task.

At some point the library may be published to the public Maven repository if there is any interest.

Until that happens, use the gradle Publish task 'publishToMavenLocal' to run a build and publish the artifacts produced to a local maven repository. Note if the publishToMavenLocal task is run on a Mac, it can build **all** the supported targets. Publishing on Linux or Windows will not build the apple targets. 

## Dependency

Define the library as a gradle dependency (assumes mavenLocal is defined as a repo in your build.gradle scripts):

```
    dependencies {
        implementation("com.oldguy:kmp-crypto:0.1.0")
        implementation("com.oldguy:kmp-io:0.1.1")
    }  
```

## Coroutine support

Since Most Crypto is CPU intensive, it typically should not be run on the main thread unless doing trivially small payloads. So the main processing functions are typically suspend functions for use with the Dispatchers.Default or Dispatchers.IO coroutine scopes.

## SourceSet structure

- commonMain has most of the code in one package.
- commonTest has the unit tests that are platform-independent
- androidMain has the platform-specific implementations using Android's java support. Depends on commonMain
- androidTest has the platform-specific unit tests using Android's java support. For example, the KMP ByteBuffer functionality is compared to the equivalenyt usage of Android's java.nio.ByteBuffer. Depends on commonTest
- appleNativeMain has the apple-specific implementations that are common across Mac, IOS and IOS Simulator,  invoked with Kotlin Native
- iosArm64Main and iosX64Main has IOS-specific code invoked with Kotlin Native. Depends on appleNativeMain and commonMain
- macosX64Main has any mac-specific code invoked with Kotlin Native. Depends on appleNativeMain and commonMain
- jvmMain has the platform-specific implementations using Java support, nearly identical to Android. Depends on commonMain

# Example Usage

There are a few enum classes defined for use in configuring a Cipher. These will always reflect the support available in the library:

**enum class CipherModes { None, CBC, CFB, CCM, GCM, ECB }**  

Modes should be familiar to anyone that has used the Java or Bouncy Castle libraries

**enum class Paddings { None, PKCS7 }** 

**enum class Digests { None, SHA1, SHA256, SHA384, SHA512, MD5, MD4, MD2, RIPEMD128, RIPEMD160, Whirlpool }**  

Digests can be used for stand-alone hashes, and are usable in key configurations that require desire a hash or hash+salt of a key

These enums are usable in the DSL syntax, which is intended to be flexible.

A DSL is used to build a Cipher instance which also has basic processing functions for the common use cases.

## AES Encrypt then decrypt a payload

This example configures an AES engine using a String key, CBC mode, and an SHA256 key digest. It configures the Cipher and its key using an initialization vector generated by a SecureRandom implementation of the size dictated by the configuration. It then encrypts an incoming buffer, then decrypts it.  The syntax used supports any number of incoming buffers until an empty buffer indicates end of data. It produces encrypted data in a series of buffers until end of input. Output buffers will typically be close to 4K on each call, with the last call being smaller.  The size of the output buffer is controllable using the **bufferSize** property in the DSL.

```
      Cipher.build {
          engine { aes() }
          mode = CipherModes.GCM
          key {
              stringKey = "SomeStringPassword" // encoded using UTF-8 by default, see stringKeyCharset
              iv = randomIV()
              hashKeyLengthBits = 256
              keyDigest = Digests.SHA256
          }
      }.apply {
          val payload = UByteBuffer(Charset(Charsets.Utf8).encode("Any payload string"))
          var encrypted = UByteBuffer(bufferSize)
          var decrypted = UByteBuffer(bufferSize)
          process(true, input = { payload }) {
              encrypted = it
          }
          process(false, input = { encrypted }) {
              decrypted = it
          }
      }
```

See the Cipher class javadoc for details on the various configuration options usable in the DSL.

## Next steps

If there is any interest in expanding this library to include more engines, padding algorithms, etc., or TLS or public/private key stuff or any other common cryptography functionality, please start a rep discussion thread.

Barring other interest, next ports will likely include Blowfish. SecureRandom is being reworked. The available choices vary widely depending on target platform, and the current definition implies control over the methods used that doesn't exist (yet).