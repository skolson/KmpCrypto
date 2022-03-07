package com.oldguy.crypto

import com.oldguy.common.toPosInt
import kotlin.math.max

/**
 * A padder that adds PKCS7/PKCS5 padding to a block.
 */
class PKCS7Padding : BlockCipherPadding {
    override val paddingName = "PKCS7"

    /**
     * Initialise the padder.
     *
     * @param random - a SecureRandom if available.
     */
    override fun init(random: SecureRandom) {
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    override fun addPadding(bytes: UByteArray, inOffset: Int): Int {
        var inOff = inOffset
        val code = (bytes.size - inOff).toUByte()
        while (inOff < bytes.size) {
            bytes[inOff] = code
            inOff++
        }
        return code.toInt()
    }

    /**
     * return the number of pad bytes present in the block.
     */
    override fun padCount(bytes: UByteArray): Int {
        val count = bytes.toPosInt(bytes.size - 1)
        val countAsbyte = count.toUByte()

        // constant time version
        var failed = (count > bytes.size) || (count == 0)
        for (i in bytes.indices) {
            failed = failed or ((bytes.size - i <= count) && (bytes[i] != countAsbyte))
        }
        if (failed) {
            throw IllegalStateException("pad block corrupted")
        }
        return count
    }
}

/**
 * A wrapper class that allows block ciphers to be used to process data in
 * a piecemeal fashion with padding. The PaddedBufferedBlockCipher
 * outputs a block only when the buffer is full and more data is being added,
 * or on a doFinal (unless the current block in the buffer is a pad block).
 * The default padding mechanism used is the one outlined in PKCS5/PKCS7.
 */
class PaddedBufferedBlockCipher constructor(
    cipher: BlockCipher,
    private val padding: BlockCipherPadding = PKCS7Padding()
) : BufferedBlockCipher(cipher) {
    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     * encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    override fun init(
        forEncryption: Boolean, params: CipherParameters
    ) {
        reset()
        if (params is ParametersWithRandom) {
            padding.init(params.random)
            cipher.init(forEncryption, params)
        } else {
            padding.init(SecureRandom())
            cipher.init(forEncryption, params)
        }
    }

    /**
     * return the minimum size of the output buffer required for an update
     * plus a doFinal with an input of len bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update and doFinal
     * with len bytes of input.
     */
    override fun getOutputSize(length: Int): Int {
        val total: Int = length + bufOff
        val leftOver: Int = total % buf.size
        return if (leftOver == 0) {
            if (forEncryption) {
                total + buf.size
            } else total
        } else total - leftOver + buf.size
    }

    /**
     * return the size of the output buffer required for an update
     * an input of len bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update
     * with len bytes of input.
     */
    override fun getUpdateOutputSize(length: Int): Int {
        val total: Int = length + bufOff
        val leftOver: Int = total % buf.size
        return if (leftOver == 0) {
            max(0, total - buf.size)
        } else
            total - leftOver
    }

    /**
     * process a single byte, producing an output block if neccessary.
     *
     * @param inByte the input byte.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception IllegalArgumentException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    override fun processByte(inByte: UByte, out: UByteArray, outOff: Int): Int {
        var resultLen = 0
        if (bufOff == buf.size) {
            resultLen = cipher.processBlock(buf, 0, out, outOff)
            bufOff = 0
        }
        buf[bufOff++] = inByte
        return resultLen
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param bytes the input byte array.
     * @param inOff the offset at which the input data starts.
     * @param len the number of bytes to be copied out of the input array.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception IllegalArgumentException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    override fun processBytes(
        bytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        var inOffset = inOff
        var length = len
        if (length < 0) {
            throw IllegalArgumentException("Can't have a negative input length!")
        }
        length = getUpdateOutputSize(length)
        if (length > 0) {
            if (outOff + length > out.size) {
                throw IllegalArgumentException("output buffer too short")
            }
        }
        var resultLen = 0
        val gapLen: Int = buf.size - bufOff
        if (length > gapLen) {
            bytes.copyInto(buf, bufOff, inOffset, inOffset + gapLen)
            resultLen += cipher.processBlock(buf, 0, out, outOff)
            bufOff = 0
            length -= gapLen
            inOffset += gapLen
            while (length > buf.size) {
                resultLen += cipher.processBlock(bytes, inOffset, out, outOff + resultLen)
                length -= blockSize
                inOffset += blockSize
            }
        }
        bytes.copyInto(buf, bufOff, inOffset, inOffset + length)
        bufOff += length
        return resultLen
    }

    /**
     * Process the last block in the buffer. If the buffer is currently
     * full and padding needs to be added a call to doFinal will produce
     * 2 * getBlockSize() bytes.
     *
     * @param out the array the block currently being held is copied into.
     * @param outOff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @exception IllegalStateException if there is insufficient space in out for
     * the output or we are decrypting and the input is not block size aligned.
     * @exception IllegalStateException if the underlying cipher is not
     * initialised.
     * @exception IllegalStateException if padding is expected and not found.
     */
    override fun doFinal(out: UByteArray, outOff: Int): Int {
        var resultLen = 0
        if (forEncryption) {
            if (bufOff == blockSize) {
                if (outOff + 2 * blockSize > out.size) {
                    reset()
                    throw IllegalArgumentException("output buffer too short")
                }
                resultLen = cipher.processBlock(buf, 0, out, outOff)
                bufOff = 0
            }
            padding.addPadding(buf, bufOff)
            resultLen += cipher.processBlock(buf, 0, out, outOff + resultLen)
            reset()
        } else {
            if (bufOff == blockSize) {
                resultLen = cipher.processBlock(buf, 0, buf, 0)
                bufOff = 0
            } else {
                reset()
                throw IllegalStateException("last block incomplete in decryption")
            }
            try {
                resultLen -= padding.padCount(buf)
                buf.copyInto(out, outOff, 0, resultLen)
            } finally {
                reset()
            }
        }
        return resultLen
    }
    /**
     * Create a buffered block cipher with the desired padding.
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     * @param padding the padding type.
     */
}
