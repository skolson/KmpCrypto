package com.oldguy.crypto

/**
 * Actual implementations will prove a cryptographically strong random number generator - speed is
 * much less important than randomness of results. See NIST SP 800-90Ar1
 */
expect class SecureRandom(
    mechanism: SecureRandomMechanism,
    algorithm: SecureRandomAlgorithm
) {
    constructor()

    /**
     * @param randomBytes contents of array will be filled with random bytes
     */
    fun nextBytes(randomBytes: ByteArray)

    /**
     * @param randomBytes contents of array will be filled with random bytes
     */
    fun nextBytes(randomBytes: UByteArray)

    companion object {
        val validAlgorithms: List<String>
    }
}

