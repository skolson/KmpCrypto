package com.oldguy.crypto

import com.oldguy.common.toIntShl
import com.oldguy.common.toPosInt

class BlockCipherAdapter(val cipher: StreamCipher) :
    BlockCipher {
    override val algorithmName = cipher.algorithmName
    override val blockSize = 16
    override val ivSize = blockSize

    override fun init(forEncryption: Boolean, params: CipherParameters) {
        if (params is ParametersWithIV) {
            cipher.init(forEncryption, params.parameters)
        } else if (params is KeyParameter) {
            cipher.init(forEncryption, params)
        } else {
            throw IllegalArgumentException("invalid parameters passed to $algorithmName")
        }
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        cipher.processStreamBytes(
            inBlock,
            inOff,
            blockSize,
            outBlock,
            outOff
        )
        return blockSize
    }

    override fun reset() {
        cipher.reset()
    }
}

class RC4Engine : StreamCipher {
    override val algorithmName = "RC4"

    /*
     * variables to hold the state of the RC4 engine
     * during encryption and decryption
     */
    private var engineState = UByteArray(stateLength)
    private var x = 0
    private var y = 0
    private var workingKey = UByteArray(0)

    fun resetKey(forEncryption: Boolean, keyBytes: UByteArray) {
        init(forEncryption, KeyParameter(keyBytes))
    }

    /**
     * initialise a RC4 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    override fun init(
        forEncryption: Boolean,
        params: CipherParameters
    ) {
        if (params is KeyParameter) {
            /*
             * RC4 encryption and decryption is completely
             * symmetrical, so the 'forEncryption' is
             * irrelevant.
             */
            workingKey = params.key
            resetKey(workingKey)
            return
        }
        throw IllegalArgumentException("invalid parameter passed to RC4 init - ")
    }

    override fun returnByte(inByte: UByte): UByte {
        x = (x + 1) and 0xff
        y = (engineState[x].toInt() + y) and 0xff
        // swap
        val tmp = engineState[x]
        engineState[x] = engineState[y]
        engineState[y] = tmp
        // xor
        return inByte xor (engineState[(engineState[x].toInt() + engineState[y].toInt()) and 0xff])
    }

    override fun processBytes(
        inBytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        if (inOff + len > inBytes.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        if (outOff + len > out.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        for (i in 0 until len) {
            x = (x + 1) and 0xff
            y = (engineState[x].toInt() + y) and 0xff
            // swap
            val tmp = engineState[x]
            engineState[x] = engineState[y]
            engineState[y] = tmp
            // xor
            out[i + outOff] =
                inBytes[i + inOff] xor engineState[(engineState[x].toInt() + engineState[y].toInt()) and 0xff]
        }
        return len
    }

    override fun processStreamBytes(
        bytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        processBytes(bytes, inOff, len, out, outOff)
        return len
    }

    override fun reset() {
        resetKey(workingKey)
    }

    // Private implementation
    private fun resetKey(keyBytes: UByteArray) {
        workingKey = keyBytes
        x = 0
        y = 0
        // reset the state of the engine
        for (i in 0 until stateLength) {
            engineState[i] = i.toUByte()
        }
        var i1 = 0
        var i2 = 0
        for (i in 0 until stateLength) {
            i2 = ((keyBytes[i1].toInt() and 0xff) + engineState[i].toInt() + i2) and 0xff
            // do the byte-swap inline
            val tmp = engineState[i]
            engineState[i] = engineState[i2]
            engineState[i2] = tmp
            i1 = (i1 + 1) % keyBytes.size
        }
    }

    companion object {
        private const val stateLength = 256
    }
}

class RC2Parameters constructor(key: UByteArray) : KeyParameter(key) {
    val effectiveKeyBits: Int = if (key.size > 128) 1024 else key.size * 8
}

/**
 * an implementation of RC2 as described in RFC 2268
 * "A Description of the RC2(r) Encryption Algorithm" R. Rivest.
 */
class RC2Engine : BlockCipher {
    override val algorithmName = "RC2"
    private var workingKey = IntArray(0)
    private var encrypting = false
    override val blockSize = 8
    override val ivSize = 8

    private fun generateWorkingKey(
        key: UByteArray,
        bits: Int
    ): IntArray {
        var x: Int
        val xKey = IntArray(128)
        for (i in key.indices) {
            xKey[i] = key[i].toInt() and 0xff
        }

        // Phase 1: Expand input key to 128 bytes
        var len = key.size
        if (len < 128) {
            var index = 0
            x = xKey[len - 1]
            do {
                x = piTable[(x + xKey[index++]) and 255].toInt() and 0xff
                xKey[len++] = x
            } while (len < 128)
        }

        // Phase 2 - reduce effective key size to "bits"
        len = bits + 7 shr 3
        x = piTable[xKey[128 - len] and (255 shr (7 and -bits))].toInt() and 0xff
        xKey[128 - len] = x
        for (i in 128 - len - 1 downTo 0) {
            x = piTable[x xor xKey[i + len]].toInt() and 0xff
            xKey[i] = x
        }

        // Phase 3 - copy to newKey in little-endian order
        val newKey = IntArray(64)
        for (i in newKey.indices) {
            newKey[i] = xKey[2 * i] + (xKey[2 * i + 1] shl 8)
        }
        return newKey
    }

    /**
     * This engine can limit the key to 1024 bits (128 bytes)
     * @param forEncryption true for encryption, false for decryption
     * @param key
     * @param limitKeySize if true key will be limited to 128 bytes
     */
    fun setKey(forEncryption: Boolean, key: UByteArray, limitKeySize: Boolean = true) {
        init(
            forEncryption,
            if (limitKeySize)
                RC2Parameters(key)
            else
                KeyParameter(key)
        )
    }

    /**
     * initialise a RC2 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    override fun init(
        forEncryption: Boolean,
        params: CipherParameters
    ) {
        this.encrypting = forEncryption
        workingKey = when (params) {
            is RC2Parameters -> {
                generateWorkingKey(
                    params.key,
                    params.effectiveKeyBits
                )
            }
            is KeyParameter -> {
                generateWorkingKey(params.key, params.key.size * 8)
            }
            else ->
                throw IllegalArgumentException("invalid parameter passed to RC2 init - $params")
        }
    }

    override fun reset() {}

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        if (workingKey.isEmpty()) {
            throw IllegalStateException("RC2 engine not initialised")
        }
        if (inOff + blockSize > inBlock.size) {
            throw IllegalArgumentException("input buffer too short. Size ${inBlock.size}, must be at least ${inOff + blockSize}")
        }
        if (outOff + blockSize > outBlock.size) {
            throw IllegalArgumentException("output buffer too short. Size ${outBlock.size}, must be at least ${outBlock + blockSize}")
        }
        if (encrypting) {
            encryptBlock(inBlock, inOff, outBlock, outOff)
        } else {
            decryptBlock(inBlock, inOff, outBlock, outOff)
        }
        return blockSize
    }

    /**
     * return the result rotating the 16 bit number in x left by y
     */
    private fun rotateWordLeft(
        xIn: Int,
        y: Int
    ): Int {
        var x = xIn
        x = x and 0xffff
        return x shl y or (x shr 16 - y)
    }

    private fun encryptBlock(
        inBytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ) {
        var x76: Int
        var x54: Int
        var x32: Int
        var x10: Int
        x76 = inBytes.toIntShl(inOff + 7, 8) + inBytes.toIntShl(inOff + 6)
        x54 = inBytes.toIntShl(inOff + 5, 8) + inBytes.toIntShl(inOff + 4)
        x32 = inBytes.toIntShl(inOff + 3, 8) + inBytes.toIntShl(inOff + 2)
        x10 = inBytes.toIntShl(inOff + 1, 8) + inBytes.toIntShl(inOff)
        var i = 0
        while (i <= 16) {
            x10 = rotateWordLeft(
                x10 + (x32 and x76.inv()) + (x54 and x76) + workingKey[i],
                1
            )
            x32 = rotateWordLeft(
                x32 + (x54 and x10.inv()) + (x76 and x10) + workingKey[i + 1],
                2
            )
            x54 = rotateWordLeft(
                x54 + (x76 and x32.inv()) + (x10 and x32) + workingKey[i + 2],
                3
            )
            x76 = rotateWordLeft(
                x76 + (x10 and x54.inv()) + (x32 and x54) + workingKey[i + 3],
                5
            )
            i += 4
        }
        x10 += workingKey[x76 and 63]
        x32 += workingKey[x10 and 63]
        x54 += workingKey[x32 and 63]
        x76 += workingKey[x54 and 63]

        i = 20
        while (i <= 40) {
            x10 = rotateWordLeft(
                x10 + (x32 and x76.inv()) + (x54 and x76) + workingKey[i],
                1
            )
            x32 = rotateWordLeft(
                x32 + (x54 and x10.inv()) + (x76 and x10) + workingKey[i + 1],
                2
            )
            x54 = rotateWordLeft(
                x54 + (x76 and x32.inv()) + (x10 and x32) + workingKey[i + 2],
                3
            )
            x76 = rotateWordLeft(
                x76 + (x10 and x54.inv()) + (x32 and x54) + workingKey[i + 3],
                5
            )
            i += 4
        }

        x10 += workingKey[x76 and 63]
        x32 += workingKey[x10 and 63]
        x54 += workingKey[x32 and 63]
        x76 += workingKey[x54 and 63]
        i = 44
        while (i < 64) {
            x10 = rotateWordLeft(x10 + (x32 and x76.inv()) + (x54 and x76) + workingKey[i], 1)
            x32 = rotateWordLeft(x32 + (x54 and x10.inv()) + (x76 and x10) + workingKey[i + 1], 2)
            x54 = rotateWordLeft(x54 + (x76 and x32.inv()) + (x10 and x32) + workingKey[i + 2], 3)
            x76 = rotateWordLeft(x76 + (x10 and x54.inv()) + (x32 and x54) + workingKey[i + 3], 5)
            i += 4
        }
        out[outOff + 0] = x10.toUByte()
        out[outOff + 1] = (x10 shr 8).toUByte()
        out[outOff + 2] = x32.toUByte()
        out[outOff + 3] = (x32 shr 8).toUByte()
        out[outOff + 4] = x54.toUByte()
        out[outOff + 5] = (x54 shr 8).toUByte()
        out[outOff + 6] = x76.toUByte()
        out[outOff + 7] = (x76 shr 8).toUByte()
    }

    private fun decryptBlock(
        inBytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ) {
        var x76: Int
        var x54: Int
        var x32: Int
        var x10: Int
        x76 = inBytes.toIntShl(inOff + 7, 8) + inBytes.toIntShl(inOff + 6)
        x54 = inBytes.toIntShl(inOff + 5, 8) + inBytes.toIntShl(inOff + 4)
        x32 = inBytes.toIntShl(inOff + 3, 8) + inBytes.toIntShl(inOff + 2)
        x10 = inBytes.toIntShl(inOff + 1, 8) + inBytes.toPosInt(inOff)

        var i = 60
        while (i >= 44) {
            x76 = rotateWordLeft(
                x76,
                11
            ) - ((x10 and x54.inv()) + (x32 and x54) + workingKey[i + 3])
            x54 = rotateWordLeft(
                x54,
                13
            ) - ((x76 and x32.inv()) + (x10 and x32) + workingKey[i + 2])
            x32 = rotateWordLeft(
                x32,
                14
            ) - ((x54 and x10.inv()) + (x76 and x10) + workingKey[i + 1])
            x10 = rotateWordLeft(
                x10,
                15
            ) - ((x32 and x76.inv()) + (x54 and x76) + workingKey[i])
            i -= 4
        }
        x76 -= workingKey[x54 and 63]
        x54 -= workingKey[x32 and 63]
        x32 -= workingKey[x10 and 63]
        x10 -= workingKey[x76 and 63]

        i = 40
        while (i >= 20) {
            x76 = rotateWordLeft(
                x76,
                11
            ) - ((x10 and x54.inv()) + (x32 and x54) + workingKey[i + 3])
            x54 = rotateWordLeft(
                x54,
                13
            ) - ((x76 and x32.inv()) + (x10 and x32) + workingKey[i + 2])
            x32 = rotateWordLeft(
                x32,
                14
            ) - ((x54 and x10.inv()) + (x76 and x10) + workingKey[i + 1])
            x10 = rotateWordLeft(
                x10,
                15
            ) - ((x32 and x76.inv()) + (x54 and x76) + workingKey[i])
            i -= 4
        }

        x76 -= workingKey[x54 and 63]
        x54 -= workingKey[x32 and 63]
        x32 -= workingKey[x10 and 63]
        x10 -= workingKey[x76 and 63]
        i = 16
        while (i >= 0) {
            x76 = rotateWordLeft(
                x76,
                11
            ) - ((x10 and x54.inv()) + (x32 and x54) + workingKey[i + 3])
            x54 = rotateWordLeft(
                x54,
                13
            ) - ((x76 and x32.inv()) + (x10 and x32) + workingKey[i + 2])
            x32 = rotateWordLeft(
                x32,
                14
            ) - ((x54 and x10.inv()) + (x76 and x10) + workingKey[i + 1])
            x10 = rotateWordLeft(x10, 15) - ((x32 and x76.inv()) + (x54 and x76) + workingKey[i])
            i -= 4
        }
        out[outOff + 0] = x10.toUByte()
        out[outOff + 1] = (x10 shr 8).toUByte()
        out[outOff + 2] = x32.toUByte()
        out[outOff + 3] = (x32 shr 8).toUByte()
        out[outOff + 4] = x54.toUByte()
        out[outOff + 5] = (x54 shr 8).toUByte()
        out[outOff + 6] = x76.toUByte()
        out[outOff + 7] = (x76 shr 8).toUByte()
    }

    companion object {
        //
        // the values we use for key expansion (based on the digits of PI)
        //
        private val piTable = ubyteArrayOf(
            0xd9u,
            0x78u,
            0xf9u,
            0xc4u,
            0x19u,
            0xddu,
            0xb5u,
            0xedu,
            0x28u,
            0xe9u,
            0xfdu,
            0x79u,
            0x4au,
            0xa0u,
            0xd8u,
            0x9du,
            0xc6u,
            0x7eu,
            0x37u,
            0x83u,
            0x2bu,
            0x76u,
            0x53u,
            0x8eu,
            0x62u,
            0x4cu,
            0x64u,
            0x88u,
            0x44u,
            0x8bu,
            0xfbu,
            0xa2u,
            0x17u,
            0x9au,
            0x59u,
            0xf5u,
            0x87u,
            0xb3u,
            0x4fu,
            0x13u,
            0x61u,
            0x45u,
            0x6du,
            0x8du,
            0x9u,
            0x81u,
            0x7du,
            0x32u,
            0xbdu,
            0x8fu,
            0x40u,
            0xebu,
            0x86u,
            0xb7u,
            0x7bu,
            0xbu,
            0xf0u,
            0x95u,
            0x21u,
            0x22u,
            0x5cu,
            0x6bu,
            0x4eu,
            0x82u,
            0x54u,
            0xd6u,
            0x65u,
            0x93u,
            0xceu,
            0x60u,
            0xb2u,
            0x1cu,
            0x73u,
            0x56u,
            0xc0u,
            0x14u,
            0xa7u,
            0x8cu,
            0xf1u,
            0xdcu,
            0x12u,
            0x75u,
            0xcau,
            0x1fu,
            0x3bu,
            0xbeu,
            0xe4u,
            0xd1u,
            0x42u,
            0x3du,
            0xd4u,
            0x30u,
            0xa3u,
            0x3cu,
            0xb6u,
            0x26u,
            0x6fu,
            0xbfu,
            0xeu,
            0xdau,
            0x46u,
            0x69u,
            0x7u,
            0x57u,
            0x27u,
            0xf2u,
            0x1du,
            0x9bu,
            0xbcu,
            0x94u,
            0x43u,
            0x3u,
            0xf8u,
            0x11u,
            0xc7u,
            0xf6u,
            0x90u,
            0xefu,
            0x3eu,
            0xe7u,
            0x6u,
            0xc3u,
            0xd5u,
            0x2fu,
            0xc8u,
            0x66u,
            0x1eu,
            0xd7u,
            0x8u,
            0xe8u,
            0xeau,
            0xdeu,
            0x80u,
            0x52u,
            0xeeu,
            0xf7u,
            0x84u,
            0xaau,
            0x72u,
            0xacu,
            0x35u,
            0x4du,
            0x6au,
            0x2au,
            0x96u,
            0x1au,
            0xd2u,
            0x71u,
            0x5au,
            0x15u,
            0x49u,
            0x74u,
            0x4bu,
            0x9fu,
            0xd0u,
            0x5eu,
            0x4u,
            0x18u,
            0xa4u,
            0xecu,
            0xc2u,
            0xe0u,
            0x41u,
            0x6eu,
            0xfu,
            0x51u,
            0xcbu,
            0xccu,
            0x24u,
            0x91u,
            0xafu,
            0x50u,
            0xa1u,
            0xf4u,
            0x70u,
            0x39u,
            0x99u,
            0x7cu,
            0x3au,
            0x85u,
            0x23u,
            0xb8u,
            0xb4u,
            0x7au,
            0xfcu,
            0x2u,
            0x36u,
            0x5bu,
            0x25u,
            0x55u,
            0x97u,
            0x31u,
            0x2du,
            0x5du,
            0xfau,
            0x98u,
            0xe3u,
            0x8au,
            0x92u,
            0xaeu,
            0x5u,
            0xdfu,
            0x29u,
            0x10u,
            0x67u,
            0x6cu,
            0xbau,
            0xc9u,
            0xd3u,
            0x0u,
            0xe6u,
            0xcfu,
            0xe1u,
            0x9eu,
            0xa8u,
            0x2cu,
            0x63u,
            0x16u,
            0x1u,
            0x3fu,
            0x58u,
            0xe2u,
            0x89u,
            0xa9u,
            0xdu,
            0x38u,
            0x34u,
            0x1bu,
            0xabu,
            0x33u,
            0xffu,
            0xb0u,
            0xbbu,
            0x48u,
            0xcu,
            0x5fu,
            0xb9u,
            0xb1u,
            0xcdu,
            0x2eu,
            0xc5u,
            0xf3u,
            0xdbu,
            0x47u,
            0xe5u,
            0xa5u,
            0x9cu,
            0x77u,
            0xau,
            0xa6u,
            0x20u,
            0x68u, 0xfeu, 0x7fu, 0xc1u, 0xadu
        ).toByteArray()
    }
}
