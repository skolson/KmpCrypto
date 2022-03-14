# Change Log

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