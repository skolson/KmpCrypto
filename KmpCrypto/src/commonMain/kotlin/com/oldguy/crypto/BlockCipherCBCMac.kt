package com.oldguy.crypto

/**
 * standard CBC Block Cipher MAC - if no padding is specified the default of
 * pad of zeroes is used.
 *
 * create a standard MAC based on a block cipher with the size of the
 * MAC been given in bits. This class uses CBC mode as the basis for the
 * MAC generation.
 *
 *
 * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
 * or 16 bits if being used as a data authenticator (FIPS Publication 113),
 * and in general should be less than the size of the block cipher as it reduces
 * the chance of an exhaustive attack (see Handbook of Applied Cryptography).
 *
 * @param cipherIn the cipher to be used as the basis of the MAC generation.
 * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
 * @param padding the padding to be used to complete the last block.
 */
class CBCBlockCipherMac(
    cipherIn: BlockCipher,
    macSizeInBits: Int,
    private val padding: BlockCipherPadding?
) : Mac {
    private val cipher = CBCBlockCipher(cipherIn)
    override val algorithmName = cipher.algorithmName

    override val macSize = macSizeInBits / 8
    private val mac = UByteArray(cipher.blockSize)
    private val buf = UByteArray(cipher.blockSize)
    private var bufOff = 0

    /**
     * create a standard MAC based on a CBC block cipher. This will produce an
     * authentication code half the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     */
    constructor(
        cipher: BlockCipher
    ) : this(cipher, cipher.blockSize * 8 / 2, null)

    /**
     * create a standard MAC based on a CBC block cipher. This will produce an
     * authentication code half the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param padding the padding to be used to complete the last block.
     */
    constructor(
        cipher: BlockCipher,
        padding: BlockCipherPadding?
    ) : this(cipher, cipher.blockSize * 8 / 2, padding)

    /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits. This class uses CBC mode as the basis for the
     * MAC generation.
     *
     *
     * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
     * or 16 bits if being used as a data authenticator (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see Handbook of Applied Cryptography).
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
     */
    constructor(
        cipher: BlockCipher,
        macSizeInBits: Int
    ) : this(cipher, macSizeInBits, null)

    override fun init(params: CipherParameters) {
        reset()
        cipher.init(true, params)
    }

    override fun update(byte: UByte) {
        if (bufOff == buf.size) {
            cipher.processBlock(buf, 0, mac, 0)
            bufOff = 0
        }
        buf[bufOff++] = byte
    }

    override fun update(bytes: UByteArray, inOffset: Int, length: Int) {
        var inOff = inOffset
        var len = length
        if (len < 0) {
            throw IllegalArgumentException("Can't have a negative input length")
        }
        val blockSize = cipher.blockSize
        val gapLen = blockSize - bufOff
        if (len > gapLen) {
            bytes.copyInto(buf, bufOff, inOff, bufOff + gapLen)
            cipher.processBlock(buf, 0, mac, 0)
            bufOff = 0
            len -= gapLen
            inOff += gapLen
            while (len > blockSize) {
                cipher.processBlock(bytes, inOff, mac, 0)
                len -= blockSize
                inOff += blockSize
            }
        }
        bytes.copyInto(buf, bufOff, inOff, bufOff + len)
        bufOff += len
    }

    override fun doFinal(out: UByteArray, outOffset: Int): Int {
        val blockSize: Int = cipher.blockSize
        if (padding == null) {
            //
            // pad with zeroes
            //
            while (bufOff < blockSize) {
                buf[bufOff] = 0u
                bufOff++
            }
        } else {
            if (bufOff == blockSize) {
                cipher.processBlock(buf, 0, mac, 0)
                bufOff = 0
            }
            padding.addPadding(buf, bufOff)
        }
        cipher.processBlock(buf, 0, mac, 0)
        mac.copyInto(out, outOffset, 0, macSize)
        reset()
        return macSize
    }

    /**
     * Reset the mac generator.
     */
    override fun reset() {
        /*
         * clean the buffer.
         */
        for (i in buf.indices) {
            buf[i] = 0u
        }
        bufOff = 0

        /*
         * reset the underlying cipher.
         */cipher.reset()
    }
}
