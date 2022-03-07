package com.oldguy.crypto

import com.oldguy.common.getIntAt
import com.oldguy.common.toIntShl

/**
 * an implementation of the AES (Rijndael), from FIPS-197.
 *
 *
 * For further details see: [http://csrc.nist.gov/encryption/aes/](http://csrc.nist.gov/encryption/aes/).
 *
 * This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
 * [http://fp.gladman.plus.com/cryptography_technology/rijndael/](http://fp.gladman.plus.com/cryptography_technology/rijndael/)
 *
 * There are three levels of tradeoff of speed vs memory
 * Because java has no preprocessor, they are written as three separate classes from which to choose
 *
 * The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
 * and 4 for decryption.
 *
 * The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
 * adding 12 rotate operations per round to compute the values contained in the other tables from
 * the contents of the first.
 *
 * The slowest version uses no static tables at all and computes the values in each round.
 *
 *
 * This file contains the middle performance version with 2Kbytes of static tables for round precomputation.
 *
 * default constructor - 128 bit block size.
 */
class AESEngine : BlockCipher {
    override val algorithmName = "AES"
    override val blockSize = 16

    private var rounds = 0
    private lateinit var workingKey: Array<IntArray>
    private var c0 = 0
    private var c1 = 0
    private var c2 = 0
    private var c3 = 0
    private var forEncryption = false
    private var s = UByteArray(0)

    /**
     * Calculate the necessary round keys
     * The number of calculations depends on key size and block size
     * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
     * This code is written assuming those are the only possible values
     */
    private fun generateWorkingKey(key: UByteArray, forEncryption: Boolean): Array<IntArray> {
        val keyLen = key.size
        if (keyLen < 16 || keyLen > 32 || keyLen and 7 != 0) {
            throw IllegalArgumentException("Key length not 128/192/256 bits.")
        }
        val kC = keyLen ushr 2
        rounds =
            kC + 6 // This is not always true for the generalized Rijndael that allows larger block sizes
        val w = Array(rounds + 1) {
            IntArray(
                4
            )
        } // 4 words in a block
        when (kC) {
            4 -> {
                var t0 = key.getIntAt(0)
                w[0][0] = t0
                var t1 = key.getIntAt(4)
                w[0][1] = t1
                var t2 = key.getIntAt(8)
                w[0][2] = t2
                var t3 = key.getIntAt(12)
                w[0][3] = t3
                var i = 1
                while (i <= 10) {
                    val u = subWord(shift(t3, 8)) xor rcon[i - 1]
                    t0 = t0 xor u
                    w[i][0] = t0
                    t1 = t1 xor t0
                    w[i][1] = t1
                    t2 = t2 xor t1
                    w[i][2] = t2
                    t3 = t3 xor t2
                    w[i][3] = t3
                    ++i
                }
            }
            6 -> {
                var t0 = key.getIntAt(0)
                w[0][0] = t0
                var t1 = key.getIntAt(4)
                w[0][1] = t1
                var t2 = key.getIntAt(8)
                w[0][2] = t2
                var t3 = key.getIntAt(12)
                w[0][3] = t3
                var t4 = key.getIntAt(16)
                w[1][0] = t4
                var t5 = key.getIntAt(20)
                w[1][1] = t5
                var rcon = 1
                var u = subWord(shift(t5, 8)) xor rcon
                rcon = rcon shl 1
                t0 = t0 xor u
                w[1][2] = t0
                t1 = t1 xor t0
                w[1][3] = t1
                t2 = t2 xor t1
                w[2][0] = t2
                t3 = t3 xor t2
                w[2][1] = t3
                t4 = t4 xor t3
                w[2][2] = t4
                t5 = t5 xor t4
                w[2][3] = t5
                var i = 3
                while (i < 12) {
                    u = subWord(shift(t5, 8)) xor rcon
                    rcon = rcon shl 1
                    t0 = t0 xor u
                    w[i][0] = t0
                    t1 = t1 xor t0
                    w[i][1] = t1
                    t2 = t2 xor t1
                    w[i][2] = t2
                    t3 = t3 xor t2
                    w[i][3] = t3
                    t4 = t4 xor t3
                    w[i + 1][0] = t4
                    t5 = t5 xor t4
                    w[i + 1][1] = t5
                    u = subWord(shift(t5, 8)) xor rcon
                    rcon = rcon shl 1
                    t0 = t0 xor u
                    w[i + 1][2] = t0
                    t1 = t1 xor t0
                    w[i + 1][3] = t1
                    t2 = t2 xor t1
                    w[i + 2][0] = t2
                    t3 = t3 xor t2
                    w[i + 2][1] = t3
                    t4 = t4 xor t3
                    w[i + 2][2] = t4
                    t5 = t5 xor t4
                    w[i + 2][3] = t5
                    i += 3
                }
                u = subWord(shift(t5, 8)) xor rcon
                t0 = t0 xor u
                w[12][0] = t0
                t1 = t1 xor t0
                w[12][1] = t1
                t2 = t2 xor t1
                w[12][2] = t2
                t3 = t3 xor t2
                w[12][3] = t3
            }
            8 -> {
                var t0 = key.getIntAt(0)
                w[0][0] = t0
                var t1 = key.getIntAt(4)
                w[0][1] = t1
                var t2 = key.getIntAt(8)
                w[0][2] = t2
                var t3 = key.getIntAt(12)
                w[0][3] = t3
                var t4 = key.getIntAt(16)
                w[1][0] = t4
                var t5 = key.getIntAt(20)
                w[1][1] = t5
                var t6 = key.getIntAt(24)
                w[1][2] = t6
                var t7 = key.getIntAt(28)
                w[1][3] = t7
                var u: Int
                var rcon = 1
                var i = 2
                while (i < 14) {
                    u = subWord(shift(t7, 8)) xor rcon
                    rcon = rcon shl 1
                    t0 = t0 xor u
                    w[i][0] = t0
                    t1 = t1 xor t0
                    w[i][1] = t1
                    t2 = t2 xor t1
                    w[i][2] = t2
                    t3 = t3 xor t2
                    w[i][3] = t3
                    u = subWord(t3)
                    t4 = t4 xor u
                    w[i + 1][0] = t4
                    t5 = t5 xor t4
                    w[i + 1][1] = t5
                    t6 = t6 xor t5
                    w[i + 1][2] = t6
                    t7 = t7 xor t6
                    w[i + 1][3] = t7
                    i += 2
                }
                u = subWord(shift(t7, 8)) xor rcon
                t0 = t0 xor u
                w[14][0] = t0
                t1 = t1 xor t0
                w[14][1] = t1
                t2 = t2 xor t1
                w[14][2] = t2
                t3 = t3 xor t2
                w[14][3] = t3
            }
            else -> {
                throw IllegalStateException("Should never get here")
            }
        }
        if (!forEncryption) {
            for (j in 1 until rounds) {
                for (i in 0..3) {
                    w[j][i] = invMcol(w[j][i])
                }
            }
        }
        return w
    }

    /**
     * Use this to change a key, will create the correct CipherParameters for this engine
     * @param forEncryption true for encryption, false for decryption
     * @param key bytes used as key
     */
    fun setKey(forEncryption: Boolean, key: UByteArray) {
        init(forEncryption, KeyParameter(key))
    }

    /**
     * initialise an AES cipher.
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
            workingKey = generateWorkingKey(params.key, forEncryption)
            this.forEncryption = forEncryption
            s = if (forEncryption) {
                S.copyOf()
            } else {
                Si.copyOf()
            }
            return
        }
        throw IllegalArgumentException("invalid parameter passed to AES init - $params")
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        if (workingKey.isEmpty()) {
            throw IllegalStateException("AES engine not initialised")
        }
        if (inOff + blockSize > inBlock.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        if (outOff + blockSize > outBlock.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        if (forEncryption) {
            unpackBlock(inBlock, inOff)
            encryptBlock(workingKey)
            packBlock(outBlock, outOff)
        } else {
            unpackBlock(inBlock, inOff)
            decryptBlock(workingKey)
            packBlock(outBlock, outOff)
        }
        return blockSize
    }

    override fun reset() {}
    private fun unpackBlock(
        bytes: UByteArray,
        off: Int
    ) {
        var index = off
        c0 = bytes.toIntShl(index++)
        c0 = c0 or bytes.toIntShl(index++, 8)
        c0 = c0 or bytes.toIntShl(index++, 16)
        c0 = c0 or bytes.toIntShl(index++, 24)
        c1 = bytes.toIntShl(index++)
        c1 = c1 or bytes.toIntShl(index++, 8)
        c1 = c1 or bytes.toIntShl(index++, 16)
        c1 = c1 or bytes.toIntShl(index++, 24)
        c2 = bytes.toIntShl(index++)
        c2 = c2 or bytes.toIntShl(index++, 8)
        c2 = c2 or bytes.toIntShl(index++, 16)
        c2 = c2 or bytes.toIntShl(index++, 24)
        c3 = bytes.toIntShl(index++)
        c3 = c3 or bytes.toIntShl(index++, 8)
        c3 = c3 or bytes.toIntShl(index++, 16)
        c3 = c3 or bytes.toIntShl(index, 24)
    }

    private fun packBlock(
        bytes: UByteArray,
        off: Int
    ) {
        var index = off
        bytes[index++] = (c0 and 0xff).toUByte()
        bytes[index++] = ((c0 shr 8) and 0xff).toUByte()
        bytes[index++] = ((c0 shr 16) and 0xff).toUByte()
        bytes[index++] = ((c0 shr 24) and 0xff).toUByte()
        bytes[index++] = (c1 and 0xff).toUByte()
        bytes[index++] = ((c1 shr 8) and 0xff).toUByte()
        bytes[index++] = ((c1 shr 16) and 0xff).toUByte()
        bytes[index++] = ((c1 shr 24) and 0xff).toUByte()
        bytes[index++] = (c2 and 0xff).toUByte()
        bytes[index++] = ((c2 shr 8) and 0xff).toUByte()
        bytes[index++] = ((c2 shr 16) and 0xff).toUByte()
        bytes[index++] = ((c2 shr 24) and 0xff).toUByte()
        bytes[index++] = (c3 and 0xff).toUByte()
        bytes[index++] = ((c3 shr 8) and 0xff).toUByte()
        bytes[index++] = ((c3 shr 16) and 0xff).toUByte()
        bytes[index] = ((c3 shr 24) and 0xff).toUByte()
    }

    private fun encryptBlock(KW: Array<IntArray>) {
        var t0 = c0 xor KW[0][0]
        var t1 = c1 xor KW[0][1]
        var t2 = c2 xor KW[0][2]
        var r = 1
        var r0: Int
        var r1: Int
        var r2: Int
        var r3 = c3 xor KW[0][3]
        while (r < rounds - 1) {
            r0 = T0[t0 and 255] xor shift(T0[t1 shr 8 and 255], 24) xor shift(
                T0[t2 shr 16 and 255], 16
            ) xor shift(
                T0[r3 shr 24 and 255], 8
            ) xor KW[r][0]
            r1 = T0[t1 and 255] xor shift(T0[t2 shr 8 and 255], 24) xor shift(
                T0[r3 shr 16 and 255], 16
            ) xor shift(
                T0[t0 shr 24 and 255], 8
            ) xor KW[r][1]
            r2 = T0[t2 and 255] xor shift(T0[r3 shr 8 and 255], 24) xor shift(
                T0[t0 shr 16 and 255], 16
            ) xor shift(
                T0[t1 shr 24 and 255], 8
            ) xor KW[r][2]
            r3 = T0[r3 and 255] xor shift(T0[t0 shr 8 and 255], 24) xor shift(
                T0[t1 shr 16 and 255], 16
            ) xor shift(
                T0[t2 shr 24 and 255], 8
            ) xor KW[r++][3]
            t0 = T0[r0 and 255] xor shift(T0[r1 shr 8 and 255], 24) xor shift(
                T0[r2 shr 16 and 255], 16
            ) xor shift(
                T0[r3 shr 24 and 255], 8
            ) xor KW[r][0]
            t1 = T0[r1 and 255] xor shift(T0[r2 shr 8 and 255], 24) xor shift(
                T0[r3 shr 16 and 255], 16
            ) xor shift(
                T0[r0 shr 24 and 255], 8
            ) xor KW[r][1]
            t2 = T0[r2 and 255] xor shift(T0[r3 shr 8 and 255], 24) xor shift(
                T0[r0 shr 16 and 255], 16
            ) xor shift(
                T0[r1 shr 24 and 255], 8
            ) xor KW[r][2]
            r3 = T0[r3 and 255] xor shift(T0[r0 shr 8 and 255], 24) xor shift(
                T0[r1 shr 16 and 255], 16
            ) xor shift(
                T0[r2 shr 24 and 255], 8
            ) xor KW[r++][3]
        }
        r0 = T0[t0 and 255] xor shift(T0[t1 shr 8 and 255], 24) xor shift(
            T0[t2 shr 16 and 255], 16
        ) xor shift(T0[r3 shr 24 and 255], 8) xor KW[r][0]
        r1 = T0[t1 and 255] xor shift(T0[t2 shr 8 and 255], 24) xor shift(
            T0[r3 shr 16 and 255], 16
        ) xor shift(T0[t0 shr 24 and 255], 8) xor KW[r][1]
        r2 = T0[t2 and 255] xor shift(T0[r3 shr 8 and 255], 24) xor shift(
            T0[t0 shr 16 and 255], 16
        ) xor shift(T0[t1 shr 24 and 255], 8) xor KW[r][2]
        r3 = T0[r3 and 255] xor shift(T0[t0 shr 8 and 255], 24) xor shift(
            T0[t1 shr 16 and 255], 16
        ) xor shift(T0[t2 shr 24 and 255], 8) xor KW[r++][3]

        // the final round's table is a simple function of S so we don't use a whole other four tables for it
        c0 = (S[r0 and 255].toInt() and 255) xor
                ((S[(r1 shr 8) and 255].toInt() and 255) shl 8) xor
                ((s[(r2 shr 16) and 255].toInt() and 255) shl 16) xor
                (s[(r3 shr 24) and 255].toInt() shl 24) xor
                KW[r][0]
        c1 = (s[r1 and 255].toInt() and 255) xor
                ((S[(r2 shr 8) and 255].toInt() and 255) shl 8) xor
                ((S[(r3 shr 16) and 255].toInt() and 255) shl 16) xor
                (s[(r0 shr 24) and 255].toInt() shl 24) xor
                KW[r][1]
        c2 = (s[r2 and 255].toInt() and 255) xor
                ((S[(r3 shr 8) and 255].toInt() and 255) shl 8) xor
                ((S[(r0 shr 16) and 255].toInt() and 255) shl 16) xor
                (S[(r1 shr 24) and 255].toInt() shl 24) xor
                KW[r][2]
        c3 = (s[r3 and 255].toInt() and 255) xor
                ((s[(r0 shr 8) and 255].toInt() and 255) shl 8) xor
                ((s[(r1 shr 16) and 255].toInt() and 255) shl 16) xor
                (S[(r2 shr 24) and 255].toInt() shl 24) xor
                KW[r][3]
    }

    private fun decryptBlock(KW: Array<IntArray>) {
        var t0 = c0 xor KW[rounds][0]
        var t1 = c1 xor KW[rounds][1]
        var t2 = c2 xor KW[rounds][2]
        var r = rounds - 1
        var r0: Int
        var r1: Int
        var r2: Int
        var r3 = c3 xor KW[rounds][3]
        while (r > 1) {
            r0 = Tinv0[t0 and 255] xor shift(Tinv0[r3 shr 8 and 255], 24) xor shift(
                Tinv0[t2 shr 16 and 255], 16
            ) xor shift(
                Tinv0[t1 shr 24 and 255], 8
            ) xor KW[r][0]
            r1 = Tinv0[t1 and 255] xor shift(Tinv0[t0 shr 8 and 255], 24) xor shift(
                Tinv0[r3 shr 16 and 255], 16
            ) xor shift(
                Tinv0[t2 shr 24 and 255], 8
            ) xor KW[r][1]
            r2 = Tinv0[t2 and 255] xor shift(Tinv0[t1 shr 8 and 255], 24) xor shift(
                Tinv0[t0 shr 16 and 255], 16
            ) xor shift(
                Tinv0[r3 shr 24 and 255], 8
            ) xor KW[r][2]
            r3 = Tinv0[r3 and 255] xor shift(Tinv0[t2 shr 8 and 255], 24) xor shift(
                Tinv0[t1 shr 16 and 255], 16
            ) xor shift(
                Tinv0[t0 shr 24 and 255], 8
            ) xor KW[r--][3]
            t0 = Tinv0[r0 and 255] xor shift(Tinv0[r3 shr 8 and 255], 24) xor shift(
                Tinv0[r2 shr 16 and 255], 16
            ) xor shift(
                Tinv0[r1 shr 24 and 255], 8
            ) xor KW[r][0]
            t1 = Tinv0[r1 and 255] xor shift(Tinv0[r0 shr 8 and 255], 24) xor shift(
                Tinv0[r3 shr 16 and 255], 16
            ) xor shift(
                Tinv0[r2 shr 24 and 255], 8
            ) xor KW[r][1]
            t2 = Tinv0[r2 and 255] xor shift(Tinv0[r1 shr 8 and 255], 24) xor shift(
                Tinv0[r0 shr 16 and 255], 16
            ) xor shift(
                Tinv0[r3 shr 24 and 255], 8
            ) xor KW[r][2]
            r3 = Tinv0[r3 and 255] xor shift(Tinv0[r2 shr 8 and 255], 24) xor shift(
                Tinv0[r1 shr 16 and 255], 16
            ) xor shift(
                Tinv0[r0 shr 24 and 255], 8
            ) xor KW[r--][3]
        }
        r0 = Tinv0[t0 and 255] xor shift(Tinv0[r3 shr 8 and 255], 24) xor shift(
            Tinv0[t2 shr 16 and 255], 16
        ) xor shift(
            Tinv0[t1 shr 24 and 255], 8
        ) xor KW[r][0]
        r1 = Tinv0[t1 and 255] xor shift(Tinv0[t0 shr 8 and 255], 24) xor shift(
            Tinv0[r3 shr 16 and 255], 16
        ) xor shift(
            Tinv0[t2 shr 24 and 255], 8
        ) xor KW[r][1]
        r2 = Tinv0[t2 and 255] xor shift(Tinv0[t1 shr 8 and 255], 24) xor shift(
            Tinv0[t0 shr 16 and 255], 16
        ) xor shift(
            Tinv0[r3 shr 24 and 255], 8
        ) xor KW[r][2]
        r3 = Tinv0[r3 and 255] xor shift(Tinv0[t2 shr 8 and 255], 24) xor shift(
            Tinv0[t1 shr 16 and 255], 16
        ) xor shift(
            Tinv0[t0 shr 24 and 255], 8
        ) xor KW[r][3]

        // the final round's table is a simple function of Si so we don't use a whole other four tables for it
        c0 = (Si[r0 and 255].toInt() and 255) xor
                ((s[(r3 shr 8) and 255].toInt() and 255) shl 8) xor
                ((s[(r2 shr 16) and 255].toInt() and 255) shl 16) xor
                (Si[(r1 shr 24) and 255].toInt() shl 24) xor
                KW[0][0]
        c1 = (s[r1 and 255].toInt() and 255) xor
                ((s[(r0 shr 8) and 255].toInt() and 255) shl 8) xor
                ((Si[(r3 shr 16) and 255].toInt() and 255) shl 16) xor
                (s[(r2 shr 24) and 255].toInt() shl 24) xor
                KW[0][1]
        c2 = (s[r2 and 255].toInt() and 255) xor
                ((Si[(r1 shr 8) and 255].toInt() and 255) shl 8) xor
                ((Si[(r0 shr 16) and 255].toInt() and 255) shl 16) xor
                (s[(r3 shr 24) and 255].toInt() shl 24) xor
                KW[0][2]
        c3 = (Si[r3 and 255].toInt() and 255) xor
                ((s[(r2 shr 8) and 255].toInt() and 255) shl 8) xor
                ((s[(r1 shr 16) and 255].toInt() and 255) shl 16) xor
                (s[(r0 shr 24) and 255].toInt() shl 24) xor
                KW[0][3]
    }

    companion object {
        // The S box
        private val S = ubyteArrayOf(
            99u,
            124u,
            119u,
            123u,
            242u,
            107u,
            111u,
            197u,
            48u,
            1u,
            103u,
            43u,
            254u,
            215u,
            171u,
            118u,
            202u,
            130u,
            201u,
            125u,
            250u,
            89u,
            71u,
            240u,
            173u,
            212u,
            162u,
            175u,
            156u,
            164u,
            114u,
            192u,
            183u,
            253u,
            147u,
            38u,
            54u,
            63u,
            247u,
            204u,
            52u,
            165u,
            229u,
            241u,
            113u,
            216u,
            49u,
            21u,
            4u,
            199u,
            35u,
            195u,
            24u,
            150u,
            5u,
            154u,
            7u,
            18u,
            128u,
            226u,
            235u,
            39u,
            178u,
            117u,
            9u,
            131u,
            44u,
            26u,
            27u,
            110u,
            90u,
            160u,
            82u,
            59u,
            214u,
            179u,
            41u,
            227u,
            47u,
            132u,
            83u,
            209u,
            0u,
            237u,
            32u,
            252u,
            177u,
            91u,
            106u,
            203u,
            190u,
            57u,
            74u,
            76u,
            88u,
            207u,
            208u,
            239u,
            170u,
            251u,
            67u,
            77u,
            51u,
            133u,
            69u,
            249u,
            2u,
            127u,
            80u,
            60u,
            159u,
            168u,
            81u,
            163u,
            64u,
            143u,
            146u,
            157u,
            56u,
            245u,
            188u,
            182u,
            218u,
            33u,
            16u,
            255u,
            243u,
            210u,
            205u,
            12u,
            19u,
            236u,
            95u,
            151u,
            68u,
            23u,
            196u,
            167u,
            126u,
            61u,
            100u,
            93u,
            25u,
            115u,
            96u,
            129u,
            79u,
            220u,
            34u,
            42u,
            144u,
            136u,
            70u,
            238u,
            184u,
            20u,
            222u,
            94u,
            11u,
            219u,
            224u,
            50u,
            58u,
            10u,
            73u,
            6u,
            36u,
            92u,
            194u,
            211u,
            172u,
            98u,
            145u,
            149u,
            228u,
            121u,
            231u,
            200u,
            55u,
            109u,
            141u,
            213u,
            78u,
            169u,
            108u,
            86u,
            244u,
            234u,
            101u,
            122u,
            174u,
            8u,
            186u,
            120u,
            37u,
            46u,
            28u,
            166u,
            180u,
            198u,
            232u,
            221u,
            116u,
            31u,
            75u,
            189u,
            139u,
            138u,
            112u,
            62u,
            181u,
            102u,
            72u,
            3u,
            246u,
            14u,
            97u,
            53u,
            87u,
            185u,
            134u,
            193u,
            29u,
            158u,
            225u,
            248u,
            152u,
            17u,
            105u,
            217u,
            142u,
            148u,
            155u,
            30u,
            135u,
            233u,
            206u,
            85u,
            40u,
            223u,
            140u,
            161u,
            137u,
            13u,
            191u,
            230u,
            66u,
            104u,
            65u,
            153u,
            45u, 15u, 176u, 84u, 187u, 22u
        )

        // The inverse S-box
        private val Si = ubyteArrayOf(
            82u,
            9u,
            106u,
            213u,
            48u,
            54u,
            165u,
            56u,
            191u,
            64u,
            163u,
            158u,
            129u,
            243u,
            215u,
            251u,
            124u,
            227u,
            57u,
            130u,
            155u,
            47u,
            255u,
            135u,
            52u,
            142u,
            67u,
            68u,
            196u,
            222u,
            233u,
            203u,
            84u,
            123u,
            148u,
            50u,
            166u,
            194u,
            35u,
            61u,
            238u,
            76u,
            149u,
            11u,
            66u,
            250u,
            195u,
            78u,
            8u,
            46u,
            161u,
            102u,
            40u,
            217u,
            36u,
            178u,
            118u,
            91u,
            162u,
            73u,
            109u,
            139u,
            209u,
            37u,
            114u,
            248u,
            246u,
            100u,
            134u,
            104u,
            152u,
            22u,
            212u,
            164u,
            92u,
            204u,
            93u,
            101u,
            182u,
            146u,
            108u,
            112u,
            72u,
            80u,
            253u,
            237u,
            185u,
            218u,
            94u,
            21u,
            70u,
            87u,
            167u,
            141u,
            157u,
            132u,
            144u,
            216u,
            171u,
            0u,
            140u,
            188u,
            211u,
            10u,
            247u,
            228u,
            88u,
            5u,
            184u,
            179u,
            69u,
            6u,
            208u,
            44u,
            30u,
            143u,
            202u,
            63u,
            15u,
            2u,
            193u,
            175u,
            189u,
            3u,
            1u,
            19u,
            138u,
            107u,
            58u,
            145u,
            17u,
            65u,
            79u,
            103u,
            220u,
            234u,
            151u,
            242u,
            207u,
            206u,
            240u,
            180u,
            230u,
            115u,
            150u,
            172u,
            116u,
            34u,
            231u,
            173u,
            53u,
            133u,
            226u,
            249u,
            55u,
            232u,
            28u,
            117u,
            223u,
            110u,
            71u,
            241u,
            26u,
            113u,
            29u,
            41u,
            197u,
            137u,
            111u,
            183u,
            98u,
            14u,
            170u,
            24u,
            190u,
            27u,
            252u,
            86u,
            62u,
            75u,
            198u,
            210u,
            121u,
            32u,
            154u,
            219u,
            192u,
            254u,
            120u,
            205u,
            90u,
            244u,
            31u,
            221u,
            168u,
            51u,
            136u,
            7u,
            199u,
            49u,
            177u,
            18u,
            16u,
            89u,
            39u,
            128u,
            236u,
            95u,
            96u,
            81u,
            127u,
            169u,
            25u,
            181u,
            74u,
            13u,
            45u,
            229u,
            122u,
            159u,
            147u,
            201u,
            156u,
            239u,
            160u,
            224u,
            59u,
            77u,
            174u,
            42u,
            245u,
            176u,
            200u,
            235u,
            187u,
            60u,
            131u,
            83u,
            153u,
            97u,
            23u,
            43u,
            4u,
            126u,
            186u,
            119u,
            214u,
            38u,
            225u,
            105u,
            20u, 99u, 85u, 33u, 12u, 125u
        )

        // vector used in calculating key schedule (powers of x in GF(256))
        private val rcon = intArrayOf(
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1b,
            0x36,
            0x6c,
            0xd8,
            0xab,
            0x4d,
            0x9a,
            0x2f,
            0x5e,
            0xbc,
            0x63,
            0xc6,
            0x97,
            0x35,
            0x6a,
            0xd4,
            0xb3,
            0x7d,
            0xfa,
            0xef,
            0xc5,
            0x91
        )

        // precomputation tables of calculations for rounds
        private val T0 = intArrayOf(
            -0x5a9c9c3a, -0x7b838308, -0x66888812, -0x7284840a, 0x0df2f2ff,
            -0x4294942a, -0x4e909022, 0x54c5c591, 0x50303060, 0x03010102,
            -0x56989832, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, -0x195454b3,
            -0x65898914, 0x45caca8f, -0x627d7de1, 0x40c9c989, -0x78828206,
            0x15fafaef, -0x14a6a64e, -0x36b8b872, 0x0bf0f0fb, -0x135252bf,
            0x67d4d4b3, -0x25d5da1, -0x155050bb, -0x406363dd, -0x85b5bad,
            -0x698d8d1c, 0x5bc0c09b, -0x3d48488b, 0x1cfdfde1, -0x516c6cc3,
            0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
            0x5c343468, -0xb5a5aaf, 0x34e5e5d1, 0x08f1f1f9, -0x6c8e8e1e,
            0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795,
            0x65232346, 0x5ec3c39d, 0x28181830, -0x5e6969c9, 0x0f05050a,
            -0x4a6565d1, 0x0907070e, 0x36121224, -0x647f7fe5, 0x3de2e2df,
            0x26ebebcd, 0x6927274e, -0x324d4d81, -0x608a8a16, 0x1b090912,
            -0x617c7ce3, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, -0x4d919124,
            -0x11a5a54c, -0x45f5fa5, -0x9adad5c, 0x4d3b3b76, 0x61d6d6b7,
            -0x314c4c83, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, -0x687b7bed,
            -0xaacac5a, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040,
            0x1ffcfce3, -0x374e4e87, -0x12a4a44a, -0x4195952c, 0x46cbcb8d,
            -0x26414199, 0x4b393972, -0x21b5b56c, -0x2bb3b368, -0x17a7a750,
            0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, -0x1a5555b1, 0x16fbfbed,
            -0x3abcbc7a, -0x28b2b266, 0x55333366, -0x6b7a7aef, -0x30baba76,
            0x10f9f9e9, 0x06020204, -0x7e808002, -0xfafaf60, 0x443c3c78,
            -0x456060db, -0x1c5757b5, -0xcaeae5e, -0x15c5ca3, -0x3fbfbf80,
            -0x757070fb, -0x526d6dc1, -0x436262df, 0x48383870, 0x04f5f5f1,
            -0x2043439d, -0x3e494989, 0x75dadaaf, 0x63212142, 0x30101020,
            0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18,
            0x35131326, 0x2fececc3, -0x1ea0a042, -0x5d6868cb, -0x33bbbb78,
            0x3917172e, 0x57c4c493, -0xd5858ab, -0x7d818104, 0x473d3d7a,
            -0x539b9b38, -0x18a2a246, 0x2b191932, -0x6a8c8c1a, -0x5f9f9f40,
            -0x677e7ee7, -0x2eb0b062, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
            -0x546f6fc5, -0x7c7777f5, -0x35b9b974, 0x29eeeec7, -0x2c474795,
            0x3c141428, 0x79dedea7, -0x1da1a144, 0x1d0b0b16, 0x76dbdbad,
            0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, -0x24b6b66e,
            0x0a06060c, 0x6c242448, -0x1ba3a348, 0x5dc2c29f, 0x6ed3d3bd,
            -0x105353bd, -0x599d9d3c, -0x576e6ec7, -0x5b6a6acf, 0x37e4e4d3,
            -0x7486860e, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, -0x48929226,
            -0x737272ff, 0x64d5d5b1, -0x2db1b164, -0x1f5656b7, -0x4b939328,
            -0x5a9a954, 0x07f4f4f3, 0x25eaeacf, -0x509a9a36, -0x7185850c,
            -0x165151b9, 0x18080810, -0x2a454591, -0x77878710, 0x6f25254a,
            0x722e2e5c, 0x241c1c38, -0xe5959a9, -0x384b4b8d, 0x51c6c697,
            0x23e8e8cb, 0x7cdddda1, -0x638b8b18, 0x211f1f3e, -0x22b4b46a,
            -0x2342429f, -0x797474f3, -0x7a7575f1, -0x6f8f8f20, 0x423e3e7c,
            -0x3b4a4a8f, -0x55999934, -0x27b7b770, 0x05030306, 0x01f6f6f7,
            0x120e0e1c, -0x5c9e9e3e, 0x5f35356a, -0x6a8a852, -0x2f464697,
            -0x6e7979e9, 0x58c1c199, 0x271d1d3a, -0x466161d9, 0x38e1e1d9,
            0x13f8f8eb, -0x4c6767d5, 0x33111122, -0x4496962e, 0x70d9d9a9,
            -0x767171f9, -0x586b6bcd, -0x496464d3, 0x221e1e3c, -0x6d7878eb,
            0x20e9e9c9, 0x49cece87, -0xaaaa56, 0x78282850, 0x7adfdfa5,
            -0x707373fd, -0x75e5ea7, -0x7f7676f7, 0x170d0d1a, -0x2540409b,
            0x31e6e6d7, -0x39bdbd7c, -0x47979730, -0x3cbebe7e, -0x4f6666d7,
            0x772d2d5a, 0x110f0f1e, -0x344f4f85, -0x3abab58, -0x29444493,
            0x3a16162c
        )
        private val Tinv0 = intArrayOf(
            0x50a7f451, 0x5365417e, -0x3c5be8e6, -0x69a1d8c6, -0x349454c5,
            -0xeba62e1, -0x54a70554, -0x6cfc1cb5, 0x55fa3020, -0x9928953,
            -0x6e893378, 0x254c02f5, -0x3281ab1, -0x2834d53b, -0x7fbbcada,
            -0x705c9d4b, 0x495ab1de, 0x671bba25, -0x67f115bb, -0x1e3f01a3,
            0x02752fc3, 0x12f04c81, -0x5c68b973, -0x39062c95, -0x18a070fd,
            -0x6a636deb, -0x14859241, -0x25a6ad6b, 0x2d83bed4, -0x2cde8ba8,
            0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899,
            -0x228e46d9, -0x49b01e42, 0x17ad88f0, 0x66ac20c9, -0x4bc53183,
            0x184adf63, -0x7dcee51b, 0x60335197, 0x457f5362, -0x1f889b4f,
            -0x7b519445, 0x1ca081fe, -0x6bd4f707, 0x58684870, 0x19fd458f,
            -0x7893216c, -0x480784ae, 0x23d373ab, -0x1dfdb48e, 0x578f1fe3,
            0x2aab5566, 0x0728ebb2, 0x03c2b52f, -0x65843a7a, -0x5af7c82d,
            -0xd78d7d0, -0x4d5a40dd, -0x4595fcfe, 0x5c8216ed, 0x2b1ccf8a,
            -0x6d4b8659, -0xf0df80d, -0x5e1d96b2, -0x320b259b, -0x2a41fafa,
            0x1f6234d1, -0x7501593c, -0x62acd1cc, -0x5faa0c5e, 0x32e18a05,
            0x75ebf6a4, 0x39ec830b, -0x55109fc0, 0x069f715e, 0x51106ebd,
            -0x675dec2, 0x3d06dd96, -0x51fac123, 0x46bde64d, -0x4a72ab6f,
            0x055dc471, 0x6fd40604, -0xeaafa0, 0x24fb9819, -0x6816422a,
            -0x33bcbf77, 0x779ed967, -0x42bd1750, -0x777476f9, 0x385b19e7,
            -0x24113787, 0x470a7ca1, -0x16f0bd84, -0x36e17b08, 0x00000000,
            -0x7c797ff7, 0x48ed2b32, -0x538feee2, 0x4e725a6c, -0x400f103,
            0x5638850f, 0x1ed5ae3d, 0x27392d36, 0x64d90f0a, 0x21a65c68,
            -0x2eaba465, 0x3a2e3624, -0x4e98f5f4, 0x0fe75793, -0x2d69114c,
            -0x616e64e5, 0x4fc5c080, -0x5ddf239f, 0x694b775a, 0x161a121c,
            0x0aba93e2, -0x1ad55f40, 0x43e0223c, 0x1d171b12, 0x0b0d090e,
            -0x5238740e, -0x465749d3, -0x3756e1ec, -0x7ae60ea9, 0x4c0775af,
            -0x44226612, -0x29f805d, -0x60d9fe09, -0x430a8da4, -0x3ac499bc,
            0x347efb5b, 0x7629438b, -0x2339dc35, 0x68fcedb6, 0x63f1e4b8,
            -0x3523ce29, 0x10856342, 0x40229713, 0x2011c684, 0x7d244a85,
            -0x7c2442e, 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, -0xccf4d24,
            -0x13ad79f3, -0x2f1c3e89, 0x6c16b32b, -0x66468f57, -0x5b76bef,
            0x2264e947, -0x3b730358, 0x1a3ff0a0, -0x27d382aa, -0x106fccde,
            -0x38b1b679, -0x3e2ec727, -0x15d3574, 0x360bd498, -0x307e0a5a,
            0x28de7aa5, 0x268eb7da, -0x5b4052c1, -0x1b62c5d4, 0x0d927850,
            -0x6433a096, 0x62467e54, -0x3dec720a, -0x17472770, 0x5ef7392e,
            -0xa503c7e, -0x417fa261, 0x7c93d069, -0x56d22a91, -0x4cedda31,
            0x3b99acc8, -0x5882e7f0, 0x6e639ce8, 0x7bbb3bdb, 0x097826cd,
            -0xbe7a692, 0x01b79aec, -0x5765b07d, 0x656e95e6, 0x7ee6ffaa,
            0x08cfbc21, -0x1917ea11, -0x26641846, -0x31c990b6, -0x2bf66016,
            -0x29834fd7, -0x504d5bcf, 0x31233f2a, 0x3094a5c6, -0x3f995dcb,
            0x37bc4e74, -0x59357d04, -0x4f2f6f20, 0x15d8a733, 0x4a9804f1,
            -0x82513bf, 0x0e50cd7f, 0x2ff69117, -0x7229b28a, 0x4db0ef43,
            0x544daacc, -0x20fb691c, -0x1c4a2e62, 0x1b886a4c, -0x47e0d33f,
            0x7f516546, 0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb,
            0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d, -0x739e2866,
            0x7a0ca137, -0x71eb07a7, -0x76c3ec15, -0x11d85632, 0x35c961b7,
            -0x121ae31f, 0x3cb1477a, 0x59dfd29c, 0x3f73f255, 0x79ce1418,
            -0x40c8388d, -0x153208ad, 0x5baafd5f, 0x146f3ddf, -0x7924bb88,
            -0x7e0c5036, 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16,
            0x0c25e2bc, -0x74b6c3d8, 0x41950dff, 0x7101a839, -0x214cf3f8,
            -0x631b4b28, -0x6f3ea99c, 0x6184cb7b, 0x70b632d5, 0x745c6c48,
            0x4257b8d0
        )

        private fun shift(r: Int, shift: Int): Int {
            return r ushr shift or (r shl -shift)
        }

        /* multiply four bytes in GF(2^8) by 'x' {02} in parallel */
        private const val m1 = -0x7f7f7f80
        private const val m2 = 0x7f7f7f7f
        private const val m3 = 0x0000001b
        private const val m4 = -0x3f3f3f40
        private const val m5 = 0x3f3f3f3f
        private fun ffMulX(x: Int): Int {
            return x and m2 shl 1 xor (x and m1 ushr 7) * m3
        }

        private fun ffMulX2(x: Int): Int {
            val t0 = x and m5 shl 2
            var t1 = x and m4
            t1 = t1 xor (t1 ushr 1)
            return t0 xor (t1 ushr 2) xor (t1 ushr 5)
        }

        /*
       The following defines provide alternative definitions of FFmulX that might
       give improved performance if a fast 32-bit multiply is not available.

       private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); }
       private static final int  m4 = 0x1b1b1b1b;
       private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); }

    */
        private fun invMcol(x: Int): Int {
            var t1: Int
            var t0 = x
            t1 = t0 xor shift(t0, 8)
            t0 = t0 xor ffMulX(t1)
            t1 = t1 xor ffMulX2(t0)
            t0 = t0 xor (t1 xor shift(t1, 16))
            return t0
        }

        private fun subWord(x: Int): Int {
            return (S[x and 255] and 255u).toInt() or
                    ((S[(x shr 8) and 255] and 255u).toInt() shl 8) or
                    ((S[(x shr 16) and 255] and 255u).toInt() shl 16) or
                    (S[(x shr 24) and 255].toInt() shl 24)
        }
    }
}
