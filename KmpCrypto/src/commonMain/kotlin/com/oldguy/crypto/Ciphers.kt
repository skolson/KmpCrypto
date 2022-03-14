package com.oldguy.crypto

import com.oldguy.common.io.RawFile
import com.oldguy.common.io.UByteBuffer
import com.oldguy.common.toHex

/**
 * This source is adapted from Bouncycastle and is intended to provide a multi-platform implementation
 */
interface CipherParameters

open class KeyParameter constructor(
    keyIn: UByteArray,
    keyOff: Int = 0,
    keyLen: Int = keyIn.size
) : CipherParameters {
    val key = keyIn.copyOfRange(keyOff, keyLen)
}

class ParametersWithIV(
    val parameters: CipherParameters,
    iv: UByteArray,
    ivOff: Int = 0,
    ivLen: Int = iv.size
) : CipherParameters {
    val iV = iv.copyOfRange(ivOff, ivLen)
}

class ParametersWithRandom(
    val parameters: CipherParameters,
    val random: SecureRandom
) : CipherParameters

/**
 * Base constructor.
 *
 * @param key key to be used by underlying cipher
 * @param macSize macSize in bits
 * @param nonce nonce to be used
 * @param associatedText initial associated text, if any
 */
class AEADParameters(
    val key: KeyParameter,
    val macSize: Int,
    val nonce: UByteArray,
    val associatedText: UByteArray
) : CipherParameters {
    /**
     * Base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     */
    constructor(key: KeyParameter, macSize: Int, nonce: UByteArray) : this(
        key,
        macSize,
        nonce,
        UByteArray(0)
    )
}

/**
 * Block cipher engines are expected to conform to this interface.
 */
interface BlockCipher {
    /**
     * Return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    val algorithmName: String

    /**
     * Return the block size for this cipher (in bytes).
     *
     * @return the block size for this cipher in bytes.
     */
    val blockSize: Int

    /**
     * Size of the initialization vector, will typically be same as blockSize unless a specific mode
     * specifies a different one.
     */
    val ivSize: Int

    /**
     * Initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     * encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    fun init(
        forEncryption: Boolean,
        params: CipherParameters
    )

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param inBlock the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param outBlock the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @return the number of bytes processed and produced.
     */
    fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int = 0
    ): Int

    /**
     * Reset the cipher. After resetting the cipher is in the same state
     * as it was after the last init (if there was one).
     */
    fun reset()
}

/**
 * A wrapper class that allows block ciphers to be used to process data in
 * a piecemeal fashion. The BufferedBlockCipher outputs a block only when the
 * buffer is full and more data is being added, or on a doFinal.
 *
 *
 * Note: in the case where the underlying cipher is either a CFB cipher or an
 * OFB one the last block may not be a multiple of the block size.
 */
open class BufferedBlockCipher(var cipher: BlockCipher, partialOk: Boolean = false) : BlockCipher {
    var buf = UByteArray(cipher.blockSize)
    var bufOff = 0
    var forEncryption = false
    override val blockSize = cipher.blockSize
    override val ivSize = cipher.ivSize
    override val algorithmName = cipher.algorithmName

    private val pgpCFB = cipher.algorithmName.contains("/PGP")
    private val partialBlockOkay = (pgpCFB || partialOk || cipher is StreamCipher) ||
            cipher.algorithmName.contains("/OpenPGP")

    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     * encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    override fun init(forEncryption: Boolean, params: CipherParameters) {
        this.forEncryption = forEncryption
        reset()
        cipher.init(forEncryption, params)
    }

    /**
     * return the size of the output buffer required for an update
     * an input of len bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update
     * with len bytes of input.
     */
    open fun getUpdateOutputSize(length: Int): Int {
        val total = length + bufOff
        val leftOver = if (pgpCFB) {
            if (forEncryption) {
                total % buf.size - (cipher.blockSize + 2)
            } else {
                total % buf.size
            }
        } else {
            total % buf.size
        }
        return total - leftOver
    }

    /**
     * return the size of the output buffer required for an update plus a
     * doFinal with an input of 'length' bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update and doFinal
     * with 'length' bytes of input.
     */
    open fun getOutputSize(
        length: Int
    ): Int {
        // Note: Can assume partialBlockOkay is true for purposes of this calculation
        return length + bufOff
    }

    /**
     * process a single byte, producing an output block if necessary.
     *
     * @param inByte the input byte.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     */
    open fun processByte(inByte: UByte, out: UByteArray, outOff: Int): Int {
        var resultLen = 0
        buf[bufOff++] = inByte
        if (bufOff == buf.size) {
            resultLen = cipher.processBlock(buf, 0, out, outOff)
            bufOff = 0
        }
        return resultLen
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        return processBytes(inBlock, inOff, inBlock.size, outBlock, outOff)
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
     */
    open fun processBytes(
        bytes: UByteArray,
        inOff: Int = 0,
        len: Int = bytes.size,
        out: UByteArray,
        outOff: Int = 0
    ): Int {
        require(len >= 0) { "Can't have a negative input length!" }
        val blockSize = blockSize
        val length = getUpdateOutputSize(len)
        if (length > 0) {
            if (outOff + length > out.size) {
                throw IllegalArgumentException("output buffer too short")
            }
        }
        var resultLen = 0
        val gapLen = buf.size - bufOff
        var workLength = len
        var offset = inOff
        if (workLength > gapLen) {
            bytes.copyInto(buf, bufOff, offset, offset + gapLen)
            resultLen += cipher.processBlock(buf, 0, out, outOff)
            bufOff = 0
            workLength -= gapLen
            offset += gapLen
            while (workLength > buf.size) {
                resultLen += cipher.processBlock(bytes, offset, out, outOff + resultLen)
                workLength -= blockSize
                offset += blockSize
            }
        }
        bytes.copyInto(buf, bufOff, offset, offset + workLength)
        bufOff += workLength
        if (bufOff == buf.size) {
            resultLen += cipher.processBlock(buf, 0, out, outOff + resultLen)
            bufOff = 0
        }
        return resultLen
    }

    /**
     * Process the last block in the buffer.
     *
     * @param out the array the block currently being held is copied into.
     * @param outOff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     */
    open fun doFinal(out: UByteArray, outOff: Int): Int {
        return try {
            var resultLen = 0
            if (outOff + bufOff > out.size) {
                throw IllegalArgumentException("output buffer too short for doFinal()")
            }
            if (bufOff != 0) {
                if (!partialBlockOkay) {
                    throw IllegalArgumentException("data not block size aligned. bufOff: $bufOff, content: ${buf.toHex()}")
                }
                cipher.processBlock(buf, 0, buf, 0)
                resultLen = bufOff
                bufOff = 0
                buf.copyInto(out, outOff, 0, resultLen)
            }
            resultLen
        } finally {
            reset()
        }
    }

    /**
     * Reset the buffer and cipher. After resetting the object is in the same
     * state as it was after the last init (if there was one).
     */
    override fun reset() {
        for (i in buf.indices) {
            buf[i] = 0u
        }
        bufOff = 0
        cipher.reset()
    }

    /**
     * Decrypt or encrypt a file, depending on how the cipher is initialized. If the cipher is
     * initialized for encryption, the destination RawFile will contain the encrypted content.
     *
     * Note, for encryption, if the IV in use is to be wrtten to the destination file, that must
     * happen before this function is called.  Similarly if the source file must be positioned
     *
     * @param source a read-mode source file to be encrypted/decrypted, starting at it's current
     * position. This [BufferedBlockCipher] must already be initialized, as the cipher
     * initialization determines the operation performed.
     * @param destination a write-mode file to receive the encrypted/decrypted content, with writing
     * beginning at the current file position. If an IV or
     * other content is to precede the processed output, that content must be written to the
     * [destination] file before invoking this function
     * @param bufferSize determines how much of the source file to process in one read. Strictly
     * a performance tuning aid, defaults to ((blockSize of the cipher) * 256) bytes.
     * @return total number of bytes written to the output
     */
    suspend fun decryptEncrypt(
        source: RawFile,
        destination: RawFile,
        bufferSize: Int = 256 * blockSize
    ): Long {
        val dataBlockSize = (bufferSize / cipher.blockSize) * cipher.blockSize
        val blockOut = UByteBuffer(getOutputSize(dataBlockSize))
        var bytesOut = 0L
        if (!partialBlockOkay)
            throw IllegalStateException("BufferedBlockCipher must allow partial blocks.")
        if (bufferSize % blockSize > 0)
            throw IllegalArgumentException("bufferSize: $bufferSize must be a multipl of cipher blockSize: $blockSize.")
        source.copyToU(destination, dataBlockSize) { blockIn, lastBlock ->
            blockOut.clear()
            val outSize = getOutputSize(blockIn.remaining)
            if (outSize > blockOut.capacity) {
                throw IllegalStateException("OutBuffer insufficient (shouldn't happen). Required: $outSize, have ${blockOut.capacity}")
            }
            blockOut.limit = processBytes(
                blockIn.contentBytes,
                0,
                blockIn.remaining,
                blockOut.contentBytes,
                0
            )
            bytesOut += blockOut.limit
            if (lastBlock) {
                val lastBytes = doFinal(blockOut.contentBytes, blockOut.limit)
                bytesOut += lastBytes
                blockOut.limit += lastBytes
            }
            blockOut
        }
        return bytesOut
    }

}
