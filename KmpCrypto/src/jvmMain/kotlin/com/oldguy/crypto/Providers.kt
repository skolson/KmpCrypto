package com.oldguy.crypto

/**
 * Actual implementations will prove a cryptographically strong random number generator - speed is
 * much less important than randomness of results. See NIST SP 800-90Ar1
 *
 * Note that Android doesn't offer this flexibility, so the arguments passed in are ignored.  In JVM
 * 9 or later implementations, these arguments do control instantiation
 */
@ExperimentalUnsignedTypes
actual class SecureRandom actual constructor(
    mechanism: SecureRandomMechanism,
    algorithm: SecureRandomAlgorithm
) {
    private lateinit var javaSecureRandom: java.security.SecureRandom

    actual constructor() : this(SecureRandomMechanism.Hash_DRBG, SecureRandomAlgorithm.SHA512) {
        javaSecureRandom = java.security.SecureRandom.getInstanceStrong()
    }

    /**
     * @param randomBytes contents of array will be filled with random bytes. Existing content is
     * overwritten.  Must have a non-zero size.
     */
    actual fun nextBytes(randomBytes: ByteArray) {
        if (randomBytes.isEmpty())
            throw IllegalArgumentException("randomBytes array must have a non-zero size")
        javaSecureRandom.nextBytes(randomBytes)
    }

    /**
     * @param randomBytes contents of array will be filled with random bytes. Existing content is
     * overwritten.  Must have a non-zero size.
     */
    actual fun nextBytes(randomBytes: UByteArray) {
        if (randomBytes.isEmpty())
            throw IllegalArgumentException("randomBytes array must have a non-zero size")
        val b = ByteArray(randomBytes.size)
        javaSecureRandom.nextBytes(b)
        b.toUByteArray().copyInto(randomBytes)
    }

    companion object {
        val validAlgorithms = java.security.Security.getAlgorithms("SecureRandom").toList()
    }
}
