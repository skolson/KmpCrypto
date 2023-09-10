# Change Log

### 0.1.4

- Kotlin 1.9.10
- Kotlinx atomicfu 0.22.0
- Kotlin coroutines 1.7.3
- Gradle 8.3
- kmp-io 0.1.4

### 0.1.3 

- Kotlin 1.7.20
- Kotlinx atomicfu 0.18.4
- Kotlin coroutines 1.6.4
- Gradle 7.5.1

### 0.1.2

- Cipher fun processOne added - convenience function for single-payload operations, no coroutine required.
- Cipher add key property as a convenience accessor for keyConfiguration.key
- Default Cipher key configuration to no key bytes and all other fields zero or empty. This default configuration is only useful when only the key bytes are used as a key. Use the [key] DSL function to create any more complex config.
- Deleted Provider interface and two implementation classes (noop and RC4)
- Default crypto engine for Cipher is AESEngine
- hashKeyLength now set when choosing Digest

### 0.1.1

- Cipher "process" function file encryption/decryption fixes. Add unit test for AES/GCM using random IV to encrypt test Zip file (Zip64 spec) using both this lib and Bouncy Castle. Verify encrypted file contents match. Then decrypt zip and verify content.

### 0.1.0 (2022-03)

- Existing full Android support
- IOS and Mac using Kotlin Native and new memory model
- Kotlin 1.6.10
- Kotlin coroutines 1.6.0
- Usable as a cocoapods framework with Mac and IOS Xcode projects
- Zip and Zip64 support
  - Compression - DEFLATE (from zip specification) or None to start

This library has been in use for more than a year in Android, but IOS support is new. Once IOS support is passing unit tests, the repo will be tagged with the initial release.