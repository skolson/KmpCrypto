package com.oldguy.crypto

import com.oldguy.common.io.ByteBuffer
import com.oldguy.common.io.Charset
import com.oldguy.common.io.Charsets
import kotlin.experimental.xor

interface EncryptionProvider {
    val name: String

    fun initialize(key: ByteArray)

    /**
     * Return a new ByteBuffer containing decrypted bytes starting at buf.position for buf.remaining
     * bytes.
     */
    fun encrypt(buf: ByteBuffer): ByteBuffer
    fun decrypt(buf: ByteBuffer): ByteBuffer

    companion object {
        val charset = Charset(Charsets.Utf16le)
        fun passwordBytes(password: String, maximumLength: Int = password.length): ByteArray {
            val str = if (password.length > maximumLength)
                password.substring(0, maximumLength)
            else
                password
            return charset.encode(str)
        }
    }
}

class NoopProvider : EncryptionProvider {
    override val name = "None"

    override fun initialize(key: ByteArray) {
    }

    override fun encrypt(buf: ByteBuffer): ByteBuffer {
        return buf
    }

    override fun decrypt(buf: ByteBuffer): ByteBuffer {
        return buf
    }
}

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

@Suppress("UNUSED_PARAMETER")
enum class SecureRandomCtr_DRBGCipher(cipherName: String) {
    AES128("AES-128"), AES_192("AES-192"), AES256("AES-256")
}

@Suppress("UNUSED_PARAMETER")
enum class SecureRandomCtr_DRBGStrength(value: Int) {
    Strength112(112), Strength128(128), Strength192(192), Strength256(256)
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
}

/**
 * Old-school symmetric algorithm. encrypt logic is identical to decrypt
 *
 * Replace this with RC4Engine
 */
class RC4Provider(
    override val name: String = "RC4"
): EncryptionProvider
{
    private var engineState = ByteArray(stateLength)
    private var x = 0
    private var y = 0

    override fun initialize(key: ByteArray) {
        for (i in 0 until stateLength) {
            engineState[i] = i.toByte()
        }
        var i1 = 0
        var i2 = 0
        for (i in 0 until stateLength) {
            i2 = ((key[i1].toInt() and 0xff) + engineState[i].toInt() + i2) and 0xff
            val tmp = engineState[i]
            engineState[i] = engineState[i2]
            engineState[i2] = tmp
            i1 = (i1 + 1) % key.size
        }
        x = 0
        y = 0
    }

    override fun encrypt(buf: ByteBuffer): ByteBuffer {
        return decrypt(buf)
    }

    override fun decrypt(buf: ByteBuffer): ByteBuffer {
        while (buf.remaining > 0) {
            val byte = buf.byte
            x = (x + 1) and 0xff
            y = (engineState[x].toInt() + y) and 0xff
            // swap
            val tmp = engineState[x]
            engineState[x] = engineState[y]
            engineState[y] = tmp
            // xor
            buf.position -= 1
            buf.byte = byte xor (engineState[(engineState[x] + engineState[y]) and 0xff])
        }
        buf.clear()
        return buf
    }

    companion object {
        private const val stateLength = 256
    }
}
