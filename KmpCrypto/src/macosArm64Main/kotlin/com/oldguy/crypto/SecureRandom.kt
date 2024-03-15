package com.oldguy.crypto

actual class SecureRandom actual constructor(
mechanism: SecureRandomMechanism,
algorithm: SecureRandomAlgorithm
) {
    /**
     * @param randomBytes contents of array will be filled with random bytes
     */
    actual fun nextBytes(randomBytes: ByteArray) {
    }

    /**
     * @param randomBytes contents of array will be filled with random bytes
     */
    actual fun nextBytes(randomBytes: UByteArray) {
    }

    actual constructor() : this(SecureRandomMechanism.Hash_DRBG, SecureRandomAlgorithm.SHA512) {
        TODO("Not yet implemented")
    }

    actual companion object {
        actual val validAlgorithms: List<String>
            get() = TODO("Not yet implemented")
    }

}