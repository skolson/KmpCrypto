package com.oldguy.crypto

import com.oldguy.common.getIntAt
import com.oldguy.common.io.Buffer
import com.oldguy.common.io.UByteBuffer

/**
 * a class that provides a basic DES engine.
 */
open class DESEngine : BlockCipher {
    override val algorithmName = "DES"
    override val blockSize = 8
    override val ivSize = 8

    private var workingKey = IntArray(0)

    /**
     * initialise a DES cipher.
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
            if (params.key.size > 8) {
                throw IllegalArgumentException("DES key too long - should be 8 bytes")
            }
            workingKey = generateWorkingKey(
                forEncryption,
                params.key
            )
            return
        }
        throw IllegalArgumentException("invalid parameter passed to DES init - $params")
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        if (workingKey.isEmpty()) {
            throw IllegalStateException("DES engine not initialised")
        }
        if (inOff + blockSize > inBlock.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        if (outOff + blockSize > outBlock.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        desFunc(workingKey, inBlock, inOff, outBlock, outOff)
        return blockSize
    }

    override fun reset() {}

    /**
     * generate an integer based working key based on our secret key
     * and what processing we are planning to do.
     *
     * Acknowledgements for this routine go to James Gillogly &amp; Phil Karn.
     * (whoever, and wherever they are!).
     */
    fun generateWorkingKey(
        encrypting: Boolean,
        key: UByteArray
    ): IntArray {
        val newKey = IntArray(32)
        val pc1m = BooleanArray(56)
        val pcr = BooleanArray(56)
        for (j in 0..55) {
            val l = pc1[j].toInt()
            pc1m[j] = key[l ushr 3].toInt() and byteBit[l and 7].toInt() != 0
        }
        for (i in 0..15) {
            val m = if (encrypting) {
                i shl 1
            } else {
                15 - i shl 1
            }
            val n = m + 1
            newKey[n] = 0
            newKey[m] = newKey[n]
            var l: Int
            for (j in 0..27) {
                l = j + totrot[i]
                if (l < 28) {
                    pcr[j] = pc1m[l]
                } else {
                    pcr[j] = pc1m[l - 28]
                }
            }
            for (j in 28..55) {
                l = j + totrot[i]
                if (l < 56) {
                    pcr[j] = pc1m[l]
                } else {
                    pcr[j] = pc1m[l - 28]
                }
            }
            for (j in 0..23) {
                if (pcr[pc2[j].toInt()]) {
                    newKey[m] = newKey[m] or bigByte[j]
                }
                if (pcr[pc2[j + 24].toInt()]) {
                    newKey[n] = newKey[n] or bigByte[j]
                }
            }
        }

        //
        // store the processed key
        //
        var i = 0
        while (i != 32) {
            val i1: Int = newKey[i]
            val i2: Int = newKey[i + 1]
            newKey[i] = ((i1 and 0x00fc0000) shl 6) or
                    ((i1 and 0x00000fc0) shl 10) or
                    ((i2 and 0x00fc0000) ushr 10) or
                    ((i2 and 0x00000fc0) ushr 6)
            newKey[i + 1] = ((i1 and 0x0003f000) shl 12) or
                    ((i1 and 0x0000003f) shl 16) or
                    ((i2 and 0x0003f000) ushr 4) or
                    (i2 and 0x0000003f)
            i += 2
        }
        return newKey
    }

    fun desFunc(
        wKey: IntArray,
        inBytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ) {
        var left = inBytes.getIntAt(inOff, false)
        var right = inBytes.getIntAt(inOff + 4, false)
        var work = ((left ushr 4) xor right) and 0x0f0f0f0f
        right = right xor work
        left = left xor (work shl 4)
        work = ((left ushr 16) xor right) and 0x0000ffff
        right = right xor work
        left = left xor (work shl 16)
        work = ((right ushr 2) xor left) and 0x33333333
        left = left xor work
        right = right xor (work shl 2)
        work = ((right ushr 8) xor left) and 0x00ff00ff
        left = left xor work
        right = right xor (work shl 8)
        right = (right shl 1) or (right ushr 31)
        work = (left xor right) and -0x55555556
        left = left xor work
        right = right xor work
        left = (left shl 1) or (left ushr 31)
        for (round in 0..7) {
            work = (right shl 28) or (right ushr 4)
            work = work xor wKey[round * 4 + 0]
            var fval: Int = SP7[work and 0x3f]
            fval = fval or SP5[(work ushr 8) and 0x3f]
            fval = fval or SP3[(work ushr 16) and 0x3f]
            fval = fval or SP1[(work ushr 24) and 0x3f]
            work = right xor wKey[round * 4 + 1]
            fval = fval or SP8[work and 0x3f]
            fval = fval or SP6[(work ushr 8) and 0x3f]
            fval = fval or SP4[(work ushr 16) and 0x3f]
            fval = fval or SP2[(work ushr 24) and 0x3f]
            left = left xor fval
            work = (left shl 28) or (left ushr 4)
            work = work xor wKey[round * 4 + 2]
            fval = SP7[work and 0x3f]
            fval = fval or SP5[(work ushr 8) and 0x3f]
            fval = fval or SP3[(work ushr 16) and 0x3f]
            fval = fval or SP1[(work ushr 24) and 0x3f]
            work = left xor wKey[round * 4 + 3]
            fval = fval or SP8[work and 0x3f]
            fval = fval or SP6[(work ushr 8) and 0x3f]
            fval = fval or SP4[(work ushr 16) and 0x3f]
            fval = fval or SP2[(work ushr 24) and 0x3f]
            right = right xor fval
        }
        right = (right shl 31) or (right ushr 1)
        work = (left xor right) and -0x55555556
        left = left xor work
        right = right xor work
        left = (left shl 31) or (left ushr 1)
        work = ((left ushr 8) xor right) and 0x00ff00ff
        right = right xor work
        left = left xor (work shl 8)
        work = ((left ushr 2) xor right) and 0x33333333
        right = right xor work
        left = left xor (work shl 2)
        work = ((right ushr 16) xor left) and 0x0000ffff
        left = left xor work
        right = right xor (work shl 16)
        work = ((right ushr 4) xor left) and 0x0f0f0f0f
        left = left xor work
        right = right xor (work shl 4)
        val buf = UByteBuffer(out, Buffer.ByteOrder.BigEndian)
        buf.position = outOff
        buf.int = right
        buf.int = left
    }

    companion object {
        /**
         * what follows is mainly taken from "Applied Cryptography", by
         * Bruce Schneier, however it also bears great resemblance to Richard
         * Outerbridge's D3DES...
         */
        //    private static final short[]    Df_Key =
        //        {
        //            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        //            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        //            0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
        //        };
        private val byteBit = shortArrayOf(
            128, 64, 32, 16, 8, 4, 2, 1
        )
        private val bigByte = intArrayOf(
            0x800000, 0x400000, 0x200000, 0x100000,
            0x80000, 0x40000, 0x20000, 0x10000,
            0x8000, 0x4000, 0x2000, 0x1000,
            0x800, 0x400, 0x200, 0x100,
            0x80, 0x40, 0x20, 0x10,
            0x8, 0x4, 0x2, 0x1
        )

        /*
     * Use the key schedule specified in the Standard (ANSI X3.92-1981).
     */
        private val pc1 = byteArrayOf(
            56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
            9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
            13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
        )
        private val totrot = byteArrayOf(
            1, 2, 4, 6, 8, 10, 12, 14,
            15, 17, 19, 21, 23, 25, 27, 28
        )
        private val pc2 = byteArrayOf(
            13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
            22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
        )
        private val SP1 = intArrayOf(
            0x01010400, 0x00000000, 0x00010000, 0x01010404,
            0x01010004, 0x00010404, 0x00000004, 0x00010000,
            0x00000400, 0x01010400, 0x01010404, 0x00000400,
            0x01000404, 0x01010004, 0x01000000, 0x00000004,
            0x00000404, 0x01000400, 0x01000400, 0x00010400,
            0x00010400, 0x01010000, 0x01010000, 0x01000404,
            0x00010004, 0x01000004, 0x01000004, 0x00010004,
            0x00000000, 0x00000404, 0x00010404, 0x01000000,
            0x00010000, 0x01010404, 0x00000004, 0x01010000,
            0x01010400, 0x01000000, 0x01000000, 0x00000400,
            0x01010004, 0x00010000, 0x00010400, 0x01000004,
            0x00000400, 0x00000004, 0x01000404, 0x00010404,
            0x01010404, 0x00010004, 0x01010000, 0x01000404,
            0x01000004, 0x00000404, 0x00010404, 0x01010400,
            0x00000404, 0x01000400, 0x01000400, 0x00000000,
            0x00010004, 0x00010400, 0x00000000, 0x01010004
        )
        private val SP2 = intArrayOf(
            -0x7fef7fe0, -0x7fff8000, 0x00008000, 0x00108020,
            0x00100000, 0x00000020, -0x7fefffe0, -0x7fff7fe0,
            -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000,
            -0x7fff8000, 0x00100000, 0x00000020, -0x7fefffe0,
            0x00108000, 0x00100020, -0x7fff7fe0, 0x00000000,
            -0x80000000, 0x00008000, 0x00108020, -0x7ff00000,
            0x00100020, -0x7fffffe0, 0x00000000, 0x00108000,
            0x00008020, -0x7fef8000, -0x7ff00000, 0x00008020,
            0x00000000, 0x00108020, -0x7fefffe0, 0x00100000,
            -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x00008000,
            -0x7ff00000, -0x7fff8000, 0x00000020, -0x7fef7fe0,
            0x00108020, 0x00000020, 0x00008000, -0x80000000,
            0x00008020, -0x7fef8000, 0x00100000, -0x7fffffe0,
            0x00100020, -0x7fff7fe0, -0x7fffffe0, 0x00100020,
            0x00108000, 0x00000000, -0x7fff8000, 0x00008020,
            -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x00108000
        )
        private val SP3 = intArrayOf(
            0x00000208, 0x08020200, 0x00000000, 0x08020008,
            0x08000200, 0x00000000, 0x00020208, 0x08000200,
            0x00020008, 0x08000008, 0x08000008, 0x00020000,
            0x08020208, 0x00020008, 0x08020000, 0x00000208,
            0x08000000, 0x00000008, 0x08020200, 0x00000200,
            0x00020200, 0x08020000, 0x08020008, 0x00020208,
            0x08000208, 0x00020200, 0x00020000, 0x08000208,
            0x00000008, 0x08020208, 0x00000200, 0x08000000,
            0x08020200, 0x08000000, 0x00020008, 0x00000208,
            0x00020000, 0x08020200, 0x08000200, 0x00000000,
            0x00000200, 0x00020008, 0x08020208, 0x08000200,
            0x08000008, 0x00000200, 0x00000000, 0x08020008,
            0x08000208, 0x00020000, 0x08000000, 0x08020208,
            0x00000008, 0x00020208, 0x00020200, 0x08000008,
            0x08020000, 0x08000208, 0x00000208, 0x08020000,
            0x00020208, 0x00000008, 0x08020008, 0x00020200
        )
        private val SP4 = intArrayOf(
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802080, 0x00800081, 0x00800001, 0x00002001,
            0x00000000, 0x00802000, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00800080, 0x00800001,
            0x00000001, 0x00002000, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002001, 0x00002080,
            0x00800081, 0x00000001, 0x00002080, 0x00800080,
            0x00002000, 0x00802080, 0x00802081, 0x00000081,
            0x00800080, 0x00800001, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00000000, 0x00802000,
            0x00002080, 0x00800080, 0x00800081, 0x00000001,
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802081, 0x00000081, 0x00000001, 0x00002000,
            0x00800001, 0x00002001, 0x00802080, 0x00800081,
            0x00002001, 0x00002080, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002000, 0x00802080
        )
        private val SP5 = intArrayOf(
            0x00000100, 0x02080100, 0x02080000, 0x42000100,
            0x00080000, 0x00000100, 0x40000000, 0x02080000,
            0x40080100, 0x00080000, 0x02000100, 0x40080100,
            0x42000100, 0x42080000, 0x00080100, 0x40000000,
            0x02000000, 0x40080000, 0x40080000, 0x00000000,
            0x40000100, 0x42080100, 0x42080100, 0x02000100,
            0x42080000, 0x40000100, 0x00000000, 0x42000000,
            0x02080100, 0x02000000, 0x42000000, 0x00080100,
            0x00080000, 0x42000100, 0x00000100, 0x02000000,
            0x40000000, 0x02080000, 0x42000100, 0x40080100,
            0x02000100, 0x40000000, 0x42080000, 0x02080100,
            0x40080100, 0x00000100, 0x02000000, 0x42080000,
            0x42080100, 0x00080100, 0x42000000, 0x42080100,
            0x02080000, 0x00000000, 0x40080000, 0x42000000,
            0x00080100, 0x02000100, 0x40000100, 0x00080000,
            0x00000000, 0x40080000, 0x02080100, 0x40000100
        )
        private val SP6 = intArrayOf(
            0x20000010, 0x20400000, 0x00004000, 0x20404010,
            0x20400000, 0x00000010, 0x20404010, 0x00400000,
            0x20004000, 0x00404010, 0x00400000, 0x20000010,
            0x00400010, 0x20004000, 0x20000000, 0x00004010,
            0x00000000, 0x00400010, 0x20004010, 0x00004000,
            0x00404000, 0x20004010, 0x00000010, 0x20400010,
            0x20400010, 0x00000000, 0x00404010, 0x20404000,
            0x00004010, 0x00404000, 0x20404000, 0x20000000,
            0x20004000, 0x00000010, 0x20400010, 0x00404000,
            0x20404010, 0x00400000, 0x00004010, 0x20000010,
            0x00400000, 0x20004000, 0x20000000, 0x00004010,
            0x20000010, 0x20404010, 0x00404000, 0x20400000,
            0x00404010, 0x20404000, 0x00000000, 0x20400010,
            0x00000010, 0x00004000, 0x20400000, 0x00404010,
            0x00004000, 0x00400010, 0x20004010, 0x00000000,
            0x20404000, 0x20000000, 0x00400010, 0x20004010
        )
        private val SP7 = intArrayOf(
            0x00200000, 0x04200002, 0x04000802, 0x00000000,
            0x00000800, 0x04000802, 0x00200802, 0x04200800,
            0x04200802, 0x00200000, 0x00000000, 0x04000002,
            0x00000002, 0x04000000, 0x04200002, 0x00000802,
            0x04000800, 0x00200802, 0x00200002, 0x04000800,
            0x04000002, 0x04200000, 0x04200800, 0x00200002,
            0x04200000, 0x00000800, 0x00000802, 0x04200802,
            0x00200800, 0x00000002, 0x04000000, 0x00200800,
            0x04000000, 0x00200800, 0x00200000, 0x04000802,
            0x04000802, 0x04200002, 0x04200002, 0x00000002,
            0x00200002, 0x04000000, 0x04000800, 0x00200000,
            0x04200800, 0x00000802, 0x00200802, 0x04200800,
            0x00000802, 0x04000002, 0x04200802, 0x04200000,
            0x00200800, 0x00000000, 0x00000002, 0x04200802,
            0x00000000, 0x00200802, 0x04200000, 0x00000800,
            0x04000002, 0x04000800, 0x00000800, 0x00200002
        )
        private val SP8 = intArrayOf(
            0x10001040, 0x00001000, 0x00040000, 0x10041040,
            0x10000000, 0x10001040, 0x00000040, 0x10000000,
            0x00040040, 0x10040000, 0x10041040, 0x00041000,
            0x10041000, 0x00041040, 0x00001000, 0x00000040,
            0x10040000, 0x10000040, 0x10001000, 0x00001040,
            0x00041000, 0x00040040, 0x10040040, 0x10041000,
            0x00001040, 0x00000000, 0x00000000, 0x10040040,
            0x10000040, 0x10001000, 0x00041040, 0x00040000,
            0x00041040, 0x00040000, 0x10041000, 0x00001000,
            0x00000040, 0x10040040, 0x00001000, 0x00041040,
            0x10001000, 0x00000040, 0x10000040, 0x10040000,
            0x10040040, 0x10000000, 0x00040000, 0x10001040,
            0x00000000, 0x10041040, 0x00040040, 0x10000040,
            0x10040000, 0x10001000, 0x10001040, 0x00000000,
            0x10041040, 0x00041000, 0x00041000, 0x00001040,
            0x00001040, 0x00040040, 0x10000000, 0x10041000
        )
    }
}

/**
 * a class that provides a basic DESede (or Triple DES) engine.
 */
class DESedeEngine(val largeKey: Boolean = false) : DESEngine() {
    private var workingKey1 = IntArray(0)
    private var workingKey2 = IntArray(0)
    private var workingKey3 = IntArray(0)
    private var forEncryption = false
    override val algorithmName = "DESede"
    override val blockSize = 8
    override val ivSize = 8
    val keySize get() = if (largeKey) 24 else 16

    /**
     * initialise a DESede cipher.
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
        if (params !is KeyParameter) {
            throw IllegalArgumentException(
                "invalid parameter passed to DESede init - $params"
            )
        }
        val keyMaster = params.key
        if (keyMaster.size != 24 && keyMaster.size != 16) {
            throw IllegalArgumentException("key size must be 16 or 24 bytes.")
        }
        if (largeKey && keyMaster.size != 24) {
            throw IllegalArgumentException("key size must be 24 bytes.")
        }
        this.forEncryption = forEncryption
        val key1 = UByteArray(8)
        keyMaster.copyInto(key1, 0, 0, key1.size)
        workingKey1 = generateWorkingKey(forEncryption, key1)
        val key2 = UByteArray(8)
        keyMaster.copyInto(key2, 0, 8, 8 + key2.size)
        workingKey2 = generateWorkingKey(!forEncryption, key2)
        if (keyMaster.size == 24) {
            val key3 = UByteArray(8)
            keyMaster.copyInto(key3, 0, 16, 16 + key3.size)
            workingKey3 = generateWorkingKey(forEncryption, key3)
        } else // 16 byte key
        {
            workingKey3 = workingKey1
        }
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        if (workingKey1.isEmpty()) {
            throw IllegalStateException("DESede engine not initialised")
        }
        if (inOff + blockSize > inBlock.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        if (outOff + blockSize > outBlock.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        val temp = UByteArray(blockSize)
        if (forEncryption) {
            desFunc(workingKey1, inBlock, inOff, temp, 0)
            desFunc(workingKey2, temp, 0, temp, 0)
            desFunc(workingKey3, temp, 0, outBlock, outOff)
        } else {
            desFunc(workingKey3, inBlock, inOff, temp, 0)
            desFunc(workingKey2, temp, 0, temp, 0)
            desFunc(workingKey1, temp, 0, outBlock, outOff)
        }
        return blockSize
    }

    override fun reset() {}
}
