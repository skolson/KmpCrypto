package com.oldguy.crypto

/**
 * A parent class for block cipher modes that do not require block aligned data to be processed, but can function in
 * a streaming mode.
 */
abstract class StreamBlockCipher protected constructor(
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    open val cipher: BlockCipher
) : BlockCipher,
    StreamCipher {

    override fun returnByte(inByte: UByte): UByte {
        return calculateByte(inByte)
    }

    override fun processBytes(
        inBytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        if (inOff + len > inBytes.size) {
            throw IllegalArgumentException("input buffer too small")
        }
        if (outOff + len > out.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        var inStart = inOff
        val inEnd = inOff + len
        var outStart = outOff
        while (inStart < inEnd) {
            out[outStart++] = calculateByte(inBytes[inStart++])
        }
        return len
    }

    protected abstract fun calculateByte(b: UByte): UByte
}

/**
 * A block cipher mode that includes authenticated encryption with a streaming mode and optional associated data.
 *
 *
 * Implementations of this interface may operate in a packet mode (where all input data is buffered and
 * processed dugin the call to [.doFinal]), or in a streaming mode (where output data is
 * incrementally produced with each call to [.processByte] or
 * [.processBytes].
 *
 * This is important to consider during decryption: in a streaming mode, unauthenticated plaintext data
 * may be output prior to the call to [.doFinal] that results in an authentication
 * failure. The higher level protocol utilising this cipher must ensure the plaintext data is handled
 * appropriately until the end of data is reached and the entire ciphertext is authenticated.
 * @see AEADParameters
 */
interface AEADBlockCipher : BlockCipher {
    /**
     * initialise the underlying cipher. Parameter can either be an AEADParameters or a ParametersWithIV object.
     *
     * @param forEncryption true if we are setting up for encryption, false otherwise.
     * @param params the necessary parameters for the underlying cipher to be initialised.
     * @exception IllegalArgumentException if the params argument is inappropriate.
     */
    override fun init(forEncryption: Boolean, params: CipherParameters)

    override val algorithmName: String

    val cipher: BlockCipher

    /**
     * Add a single byte to the associated data check.
     * <br></br>If the implementation supports it, this will be an online operation and will not retain the associated data.
     *
     * @param byte the byte to be processed.
     */
    fun processAADByte(byte: UByte)

    /**
     * Add a sequence of bytes to the associated data check.
     * <br></br>If the implementation supports it, this will be an online operation and will not retain the associated data.
     *
     * @param bytes the input byte array.
     * @param inOffset the offset into the in array where the data to be processed starts.
     * @param length the number of bytes to be processed.
     */
    fun processAADBytes(bytes: UByteArray, inOffset: Int, length: Int)

    /**
     * encrypt/decrypt a single byte.
     *
     * @param byte the byte to be processed.
     * @param out the output buffer the processed byte goes into.
     * @param outOffset the offset into the output byte array the processed data starts at.
     * @return the number of bytes written to out.
     * @exception IllegalArgumentException if the output buffer is too small.
     */
    fun processByte(byte: UByte, out: UByteArray, outOffset: Int): Int

    /**
     * process a block of bytes from in putting the result into out.
     *
     * @param bytes the input byte array.
     * @param inOffset the offset into the in array where the data to be processed starts.
     * @param length the number of bytes to be processed.
     * @param out the output buffer the processed bytes go into.
     * @param outOffset the offset into the output byte array the processed data starts at.
     * @return the number of bytes written to out.
     * @exception IllegalArgumentException if the output buffer is too small.
     */
    fun processBytes(
        bytes: UByteArray,
        inOffset: Int,
        length: Int,
        out: UByteArray,
        outOffset: Int
    ): Int

    /**
     * Finish the operation either appending or verifying the MAC at the end of the data.
     *
     * @param out space for any resulting output data.
     * @param outOffset offset into out to start copying the data at.
     * @return number of bytes written into out.
     * @throws IllegalStateException if the cipher is in an inappropriate state or if the MAC fails to match.
     */
    fun doFinal(out: UByteArray, outOffset: Int): Int

    /**
     * Return the value of the MAC associated with the last stream processed.
     *
     * @return MAC for plaintext data.
     */
    var mac: UByteArray

    /**
     * return the size of the output buffer required for a processBytes
     * an input of len bytes.
     *
     *
     * The returned size may be dependent on the initialisation of this cipher
     * and may not be accurate once subsequent input data is processed - this method
     * should be invoked immediately prior to input data being processed.
     *
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to processBytes
     * with len bytes of input.
     */
    fun getUpdateOutputSize(length: Int): Int

    /**
     * return the size of the output buffer required for a processBytes plus a
     * doFinal with an input of len bytes.
     *
     *
     * The returned size may be dependent on the initialisation of this cipher
     * and may not be accurate once subsequent input data is processed - this method
     * should be invoked immediately prior to a call to final processing of input data
     * and a call to [.doFinal].
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to processBytes and doFinal
     * with len bytes of input.
     */
    fun getOutputSize(length: Int): Int

    /**
     * Reset the cipher. After resetting the cipher is in the same state
     * as it was after the last init (if there was one).
     */
    override fun reset()
}

/**
 * Ciphers producing a key stream which can be reset to particular points in the stream implement this.
 */
interface SkippingCipher {
    /**
     * Skip numberOfBytes forwards, or backwards.
     *
     * @param numberOfBytes the number of bytes to skip (positive forward, negative backwards).
     * @return the number of bytes actually skipped.
     * @throws IllegalArgumentException if numberOfBytes is an invalid value.
     */
    fun skip(numberOfBytes: Long): Long

    /**
     * Reset the cipher and then skip forward to a given position.
     *
     * @param position the number of bytes in to set the cipher state to.
     * @return the byte position moved to.
     */
    fun seekTo(position: Long): Long

    /**
     * Return the current "position" of the cipher
     *
     * @return the current byte position.
     */
    val position: Long
}

/**
 * the interface stream ciphers conform to. Implementations will rely on UByteBuffer, since streams
 * are not directly available in Kotlin multi-platform.
 */
interface StreamCipher {
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
     * Return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    val algorithmName: String

    /**
     * encrypt/decrypt a single byte returning the result.
     *
     * @param inByte the byte to be processed.
     * @return the result of processing the input byte.
     */
    fun returnByte(inByte: UByte): UByte

    /**
     * process a block of bytes from in putting the result into out.
     *
     * @param inBytes the input byte array.
     * @param inOff the offset into the in array where the data to be processed starts.
     * @param len the number of bytes to be processed.
     * @param out the output buffer the processed bytes go into.
     * @param outOff the offset into the output byte array the processed data starts at.
     */
    fun processBytes(
        inBytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int

    fun processStreamBytes(
        bytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int

    /**
     * reset the cipher. This leaves it in the same state
     * it was at after the last init (if there was one).
     */
    fun reset()
}

/**
 * General interface for a stream cipher that supports skipping.
 */
interface SkippingStreamCipher : StreamCipher, SkippingCipher

/**
 * The base interface for implementations of message authentication codes (MACs).
 */
interface Mac {
    /**
     * Initialise the MAC.
     *
     * @param params the key and other data required by the MAC.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    fun init(params: CipherParameters)

    /**
     * Return the name of the algorithm the MAC implements.
     *
     * @return the name of the algorithm the MAC implements.
     */
    val algorithmName: String

    /**
     * Return the block size for this MAC (in bytes).
     *
     * @return the block size for this MAC in bytes.
     */
    val macSize: Int

    /**
     * add a single byte to the mac for processing.
     *
     * @param byte the byte to be processed.
     * @exception IllegalStateException if the MAC is not initialised.
     */
    fun update(byte: UByte)

    /**
     * @param bytes the array containing the input.
     * @param inOffset the index in the array the data begins at.
     * @param length the length of the input starting at inOff.
     * @exception IllegalStateException if the MAC is not initialised.
     * @exception IllegalArgumentException if there isn't enough data in in.
     */
    fun update(bytes: UByteArray, inOffset: Int, length: Int)

    /**
     * Compute the final stage of the MAC writing the output to the out
     * parameter.
     *
     *
     * doFinal leaves the MAC in the same state it was after the last init.
     *
     * @param out the array the MAC is to be output to.
     * @param outOffset the offset into the out buffer the output is to start at.
     * @exception IllegalArgumentException if there isn't enough space in out.
     * @exception IllegalStateException if the MAC is not initialised.
     */
    fun doFinal(out: UByteArray, outOffset: Int): Int

    /**
     * Reset the MAC. At the end of resetting the MAC should be in the
     * in the same state it was after the last init (if there was one).
     */
    fun reset()
}

/**
 * Block cipher padders are expected to conform to this interface
 */
interface BlockCipherPadding {
    /**
     * Initialise the padder.
     *
     * @param random the source of randomness for the padding, if required.
     */
    fun init(random: SecureRandom)

    /**
     * Return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    val paddingName: String

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     *
     *
     * Note: this assumes that the last block of plain text is always
     * passed to it inside in. i.e. if inOff is zero, indicating the
     * entire block is to be overwritten with padding the value of in
     * should be the same as the last block of plain text. The reason
     * for this is that some modes such as "trailing bit compliment"
     * base the padding on the last byte of plain text.
     *
     */
    fun addPadding(bytes: UByteArray, inOffset: Int): Int

    /**
     * return the number of pad bytes present in the block.
     * @exception IllegalArgumentException if the padding is badly formed
     * or invalid.
     */
    fun padCount(bytes: UByteArray): Int
}

class AEADBlockCipherAdapter(private val _cipher: AEADBlockCipher) :
    BlockCipher {
    override val algorithmName = _cipher.algorithmName
    override val blockSize = _cipher.cipher.blockSize
    override val ivSize = blockSize

    override fun init(forEncryption: Boolean, params: CipherParameters) {
        _cipher.init(forEncryption, params)
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        return _cipher.processBytes(inBlock, inOff, blockSize, outBlock, outOff)
    }

    override fun reset() {
        _cipher.reset()
    }
}
