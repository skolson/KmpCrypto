package com.oldguy.crypto

/**
 * NIST SP 800-90Ar1 mechanism names for strong randomness. May not be available on all platforms
 */
@Suppress("UNUSED_PARAMETER")
enum class SecureRandomMechanism(mechanism: String) {
    Hash_DRBG("Hash_DRBG"),
    HMAC_DRBG("HMAC_DRBG"),
    CTR_DRBG("CTR_DRBG")
}

/**
 * NIST SP 800-90Ar1 algorithm names for strong randomness. Note that SHA prefix algorithms are
 * for use with [SecureRandomMechanism.Hash_DRBG] and [SecureRandomMechanism.HMAC_DRBG].
 * AES prefix algorithms are for use with [SecureRandomMechanism.CTR_DRBG]
 *
 * May not be available on all platforms
 */
@Suppress("UNUSED_PARAMETER")
enum class SecureRandomAlgorithm(algorithm: String) {
    SHA224("SHA-224"),
    SHA512_224("SHA-512/224"),
    SHA256("SHA-256"),
    SHA512_256("SHA-512/256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),
    AES128("AES-128"),
    AES192("AES-192"),
    AES256("AES-256")
}


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

