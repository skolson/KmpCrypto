package com.oldguy.crypto

import com.oldguy.common.io.UByteBuffer


/**
 * implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
 */
class CBCBlockCipher(val cipher: BlockCipher) : BlockCipher {
    override val blockSize = cipher.blockSize
    override val ivSize = cipher.blockSize
    private val initVector = UByteArray(ivSize)
    private val cbcV = UByteArray(blockSize)
    private val cbcNextV = UByteArray(blockSize)
    private var encrypting = false
    override val algorithmName = "${cipher.algorithmName}/CBC"

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     *
     * @param forEncryption if true the cipher is initialised for
     * encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    override fun init(
        forEncryption: Boolean,
        params: CipherParameters
    ) {
        this.encrypting = forEncryption
        if (params is ParametersWithIV) {
            val iv = params.iV
            if (iv.size != blockSize) {
                throw IllegalArgumentException("initialisation vector must be the same length as block size")
            }
            iv.copyInto(initVector)
            reset()
            cipher.init(forEncryption, params.parameters)
        } else {
            reset()
            cipher.init(forEncryption, params)
        }
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param inBlock the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param outBlock the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception IllegalArgumentException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        return if (encrypting) encryptBlock(inBlock, inOff, outBlock, outOff) else decryptBlock(
            inBlock,
            inOff,
            outBlock,
            outOff
        )
    }

    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    override fun reset() {
        initVector.copyInto(cbcV)
        cbcNextV.fill(0u)
        cipher.reset()
    }

    /**
     * Do the appropriate chaining step for CBC mode encryption.
     *
     * @param `in` the array containing the data to be encrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception IllegalArgumentException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private fun encryptBlock(
        inBytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        if (inOff + blockSize > inBytes.size) {
            throw IllegalArgumentException("input buffer too short")
        }

        /*
         * XOR the cbcV and the input,
         * then encrypt the cbcV
         */
        for (i in 0 until blockSize) {
            cbcV[i] = cbcV[i] xor inBytes[inOff + i]
        }
        val length = cipher.processBlock(cbcV, 0, out, outOff)
        out.copyInto(cbcV, 0, outOff, outOff + cbcV.size)
        return length
    }

    /**
     * Do the appropriate chaining step for CBC mode decryption.
     *
     * @param `in` the array containing the data to be decrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the decrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception IllegalArgumentException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private fun decryptBlock(
        inBytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        if (inOff + blockSize > inBytes.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        inBytes.copyInto(cbcNextV, 0, inOff, inOff + blockSize)
        val length = cipher.processBlock(inBytes, inOff, out, outOff)

        /*
         * XOR the cbcV and the output
         */
        for (i in 0 until blockSize) {
            out[outOff + i] = out[outOff + i] xor cbcV[i]
        }

        /*
         * swap the back up buffer into next position
         */
        val tmp = cbcV.copyOf()
        cbcNextV.copyInto(cbcV)
        tmp.copyInto(cbcNextV)
        return length
    }
}

/**
 * implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
 */
class CFBBlockCipher(
    val cipher: BlockCipher,
    bitBlockSize: Int
) : BlockCipher {
    override val blockSize = bitBlockSize / 8
    override val ivSize = blockSize

    private val initVector = UByteArray(blockSize)
    private val cfbV = UByteArray(blockSize)
    private val cfbOutV = UByteArray(blockSize)

    override val algorithmName = "${cipher.algorithmName}/CFB${blockSize * 8}"
    val currentIV get() = cfbV.copyOf()

    /**
     * return the block size we are operating at.
     *
     * @return the block size we are operating at (in bytes).
     */
    private var encrypting = false
    private var byteCount = 0

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     *
     * @param forEncryption if true the cipher is initialised for
     * encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    override fun init(
        forEncryption: Boolean,
        params: CipherParameters
    ) {
        this.encrypting = forEncryption
        if (params is ParametersWithIV) {
            val iv = params.iV
            if (iv.size < initVector.size) {
                // prepend the supplied IV with zeros (per FIPS PUB 81)
                iv.copyInto(initVector, initVector.size - iv.size)
                for (i in 0 until initVector.size - iv.size) {
                    initVector[i] = 0u
                }
            } else {
                iv.copyInto(initVector, 0, 0, initVector.size)
            }
            reset()
            // if null it's an IV changed only.
            cipher.init(true, params.parameters)
        } else {
            reset()
            cipher.init(true, params)
        }
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param inBlock the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param outBlock the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception IllegalArgumentException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        return if (encrypting)
            encryptBlock(inBlock, inOff, outBlock, outOff)
        else
            decryptBlock(inBlock, inOff, outBlock, outOff)
    }

    /**
     * Do the appropriate processing for CFB mode encryption.
     *
     * @param `in` the array containing the data to be encrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception IllegalArgumentException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private fun encryptBlock(
        bytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        if (inOff + blockSize > bytes.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        if (outOff + blockSize > out.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        cipher.processBlock(cfbV, 0, cfbOutV, 0)
        /**
         * XOR the cfbV with the plaintext producing the ciphertext
         */
        for (i in 0 until blockSize) {
            out[outOff + i] = cfbOutV[i] xor bytes.get(inOff + i)
        }
        /**
         * change over the input block.
         * src, srcOff, dest, destOff, len
         */
        cfbV.copyInto(cfbV, 0, blockSize, cfbV.size)
        out.copyInto(cfbV, cfbV.size - blockSize, outOff, outOff + blockSize)
        return blockSize
    }

    /**
     * Do the appropriate processing for CFB mode decryption.
     *
     * @param `in` the array containing the data to be decrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception IllegalArgumentException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private fun decryptBlock(
        bytes: UByteArray,
        inOff: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        if (inOff + blockSize > bytes.size) {
            throw IllegalArgumentException("input buffer too short")
        }
        if (outOff + blockSize > out.size) {
            throw IllegalArgumentException("output buffer too short")
        }
        cipher.processBlock(cfbV, 0, cfbOutV, 0)
        cfbV.copyInto(cfbV, 0, blockSize, cfbV.size)
        bytes.copyInto(cfbV, cfbV.size - blockSize, inOff, inOff + blockSize)
        for (i in 0 until blockSize) {
            out[outOff + i] = cfbOutV[i] xor bytes.get(inOff + i)
        }

        return blockSize
    }

    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    override fun reset() {
        initVector.copyInto(cfbV)
        byteCount = 0
        cipher.reset()
    }
}

/**
 * Implements the Counter with Cipher Block Chaining mode (CCM) detailed in
 * NIST Special Publication 800-38C.
 *
 *
 * **Note**: this mode is a packet mode - it needs all the data up front.
 */
class CCMBlockCipher(
    override val cipher: BlockCipher
) : AEADBlockCipher {
    override val blockSize = cipher.blockSize
    override val ivSize = 8

    override val algorithmName = "${cipher.algorithmName}/CCM"
    private var forEncryption = false
    private var nonce = UByteArray(0)
    private var initialAssociatedText = UByteArray(0)
    override var mac = UByteArray(0)
    private var macSize: Int = 0
        set(value) {
            field = value
            mac = UByteArray(field)
            macBlock.copyInto(mac, 0, 0, field)
        }
    private var keyParam: CipherParameters? = null
    private val macBlock = UByteArray(blockSize)
    private val associatedTextLength get() = associatedText.position + initialAssociatedText.size
    private val hasAssociatedText: Boolean get() = associatedTextLength > 0

    private var associatedText = UByteBuffer(4096)
    private var data = UByteBuffer(4096)

    init {
        if (blockSize != 16) {
            throw IllegalArgumentException("cipher required with a block size of 16, not $blockSize.")
        }
    }

    override fun init(forEncryption: Boolean, params: CipherParameters) {
        this.forEncryption = forEncryption
        keyParam = when (params) {
            is AEADParameters -> {
                nonce = params.nonce
                initialAssociatedText = params.associatedText
                macSize = params.macSize / 8
                params.key
            }
            is ParametersWithIV -> {
                nonce = params.iV
                initialAssociatedText = UByteArray(0)
                macSize = macBlock.size / 2
                params.parameters
            }
            else ->
                throw IllegalArgumentException("invalid parameters passed to CCM: $params")
        }

        if (nonce.isEmpty() || nonce.size < 7 || nonce.size > 13) {
            throw IllegalArgumentException("nonce must have length from 7 to 13 octets. Found: ${nonce.size}")
        }
        reset()
    }

    override fun processAADByte(byte: UByte) {
        associatedText.int = byte.toInt()
    }

    override fun processAADBytes(bytes: UByteArray, inOffset: Int, length: Int) {
        // TODO: Process AAD online
        associatedText.putBytes(bytes, inOffset, length)
    }

    override fun processByte(byte: UByte, out: UByteArray, outOffset: Int): Int {
        data.int = byte.toInt()
        return 0
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        return processBytes(inBlock, inOff, inBlock.size - inOff, outBlock, outOff)
    }

    override fun processBytes(
        bytes: UByteArray,
        inOffset: Int,
        length: Int,
        out: UByteArray,
        outOffset: Int
    ): Int {
        if (bytes.size < inOffset + length) {
            throw IllegalArgumentException("Input buffer too short")
        }
        data.putBytes(bytes, inOffset, length)
        return 0
    }

    override fun doFinal(out: UByteArray, outOffset: Int): Int {
        val buf = data.contentBytes.copyOfRange(0, data.position)
        val len = processPacket(buf, 0, buf.size, out, outOffset)
        reset()
        return len
    }

    override fun reset() {
        cipher.reset()
        associatedText.rewind()
        data.rewind()
    }

    override fun getUpdateOutputSize(length: Int): Int {
        return 0
    }

    override fun getOutputSize(length: Int): Int {
        val totalData: Int = length + data.position
        if (forEncryption) {
            return totalData + macSize
        }
        return if (totalData < macSize) 0 else totalData - macSize
    }

    /**
     * Process a packet of data for either CCM decryption or encryption.
     *
     * @param `in` data for processing.
     * @param inOff offset at which data starts in the input array.
     * @param inLen length of the data in the input array.
     * @return a byte array containing the processed input..
     * @throws IllegalStateException if the cipher is not appropriately set up.
     * @throws IllegalArgumentException if the input data is truncated or the mac check fails.
     */
    fun processPacket(bytes: UByteArray, inOff: Int, inLen: Int): UByteArray {
        val output = if (forEncryption) {
            UByteArray(inLen + macSize)
        } else {
            if (inLen < macSize) {
                throw IllegalArgumentException("data too short")
            }
            UByteArray(inLen - macSize)
        }
        processPacket(bytes, inOff, inLen, output, 0)
        return output
    }

    /**
     * Process a packet of data for either CCM decryption or encryption.
     *
     * @param `in` data for processing.
     * @param inOff offset at which data starts in the input array.
     * @param inLen length of the data in the input array.
     * @param output output array.
     * @param outOff offset into output array to start putting processed bytes.
     * @return the number of bytes added to output.
     * @throws IllegalStateException if the cipher is not appropriately set up.
     * @throws IllegalArgumentException if the input data is truncated or the mac check fails,
     * or if output buffer too short.
     */
    private fun processPacket(
        bytes: UByteArray,
        inOff: Int,
        inLen: Int,
        output: UByteArray,
        outOff: Int
    ): Int {
        // Need to keep the CTR and CBC Mac parts around and reset
        if (keyParam == null) {
            throw IllegalStateException("CCM cipher unitialized.")
        }
        val n = nonce.size
        val q = 15 - n
        if (q < 4) {
            val limitLen = 1 shl 8 * q
            if (inLen >= limitLen) {
                throw IllegalStateException("CCM packet too large for choice of q.")
            }
        }
        val iv = UByteArray(blockSize)
        iv[0] = (q - 1 and 0x7).toUByte()
        nonce.copyInto(iv, 0, 1, 1 + nonce.size)
        val ctrCipher: BlockCipher = SICBlockCipher(cipher)
        ctrCipher.init(forEncryption, ParametersWithIV(keyParam!!, iv))
        val outputLen: Int
        var inIndex = inOff
        var outIndex = outOff
        if (forEncryption) {
            outputLen = inLen + macSize
            if (output.size < outputLen + outOff) {
                throw IllegalArgumentException("Output buffer too short.")
            }
            calculateMac(bytes, inOff, inLen, macBlock)
            val encMac = UByteArray(blockSize)
            ctrCipher.processBlock(macBlock, 0, encMac, 0) // S0
            while (inIndex < inOff + inLen - blockSize) // S1...
            {
                ctrCipher.processBlock(bytes, inIndex, output, outIndex)
                outIndex += blockSize
                inIndex += blockSize
            }
            val block = UByteArray(blockSize)
            bytes.copyInto(block, 0, inIndex, inLen + inOff)
            ctrCipher.processBlock(block, 0, block, 0)
            block.copyInto(output, outIndex, 0, outIndex + inLen + inOff - inIndex)
            encMac.copyInto(output, outOff + inLen, 0, macSize)
        } else {
            if (inLen < macSize) {
                throw IllegalArgumentException("data too short")
            }
            outputLen = inLen - macSize
            if (output.size < outputLen + outOff) {
                throw IllegalArgumentException("Output buffer too short.")
            }
            bytes.copyInto(macBlock, 0, inOff + outputLen, inOff + outputLen + macSize)
            ctrCipher.processBlock(macBlock, 0, macBlock, 0)
            for (i in macSize until macBlock.size) {
                macBlock[i] = 0u
            }
            while (inIndex < inOff + outputLen - blockSize) {
                ctrCipher.processBlock(bytes, inIndex, output, outIndex)
                outIndex += blockSize
                inIndex += blockSize
            }
            val block = UByteArray(blockSize)
            bytes.copyInto(block, 0, inIndex, inIndex + outputLen - (inIndex - inOff))
            ctrCipher.processBlock(block, 0, block, 0)
            block.copyInto(output, outIndex, 0, outputLen - (inIndex - inOff))
            val calculatedMacBlock = UByteArray(blockSize)
            calculateMac(output, outOff, outputLen, calculatedMacBlock)
            if (macBlock contentEquals calculatedMacBlock) {
                throw IllegalStateException("mac check in CCM failed")
            }
        }
        return outputLen
    }

    private fun calculateMac(
        data: UByteArray,
        dataOff: Int,
        dataLen: Int,
        macBlock: UByteArray
    ): Int {
        val cMac = CBCBlockCipherMac(cipher, macSize * 8)
        cMac.init(keyParam ?: throw IllegalStateException("cipher must be initialized"))
        //
        // build b0
        //
        val b0 = UByteArray(16)
        if (hasAssociatedText) {
            b0[0] = b0[0] or 0x40u
        }
        b0[0] = b0[0] or ((((cMac.macSize - 2) / 2) and 0x7) shl 3).toUByte()
        b0[0] = b0[0] or ((15 - nonce.size - 1).toUByte() and 0x7u)
        nonce.copyInto(b0, 1)
        var q = dataLen
        var count = 1
        while (q > 0) {
            b0[b0.size - count] = (q and 0xff).toUByte()
            q = q ushr 8
            count++
        }
        cMac.update(b0, 0, b0.size)

        //
        // process associated text
        //
        if (hasAssociatedText) {
            val textLength = associatedTextLength
            var extra = if (textLength < (1 shl 16) - (1 shl 8)) {
                cMac.update((textLength shr 8).toUByte())
                cMac.update(textLength.toUByte())
                2
            } else // can't go any higher than 2^32
            {
                cMac.update(0xffu)
                cMac.update(0xfeu)
                cMac.update((textLength shr 24).toUByte())
                cMac.update((textLength shr 16).toUByte())
                cMac.update((textLength shr 8).toUByte())
                cMac.update(textLength.toUByte())
                6
            }
            if (initialAssociatedText.isNotEmpty()) {
                cMac.update(initialAssociatedText, 0, initialAssociatedText.size)
            }
            if (associatedText.position > 0) {
                val buf = associatedText.contentBytes.copyOfRange(0, associatedText.position)
                cMac.update(buf, 0, buf.size)
            }
            extra = (extra + textLength) % 16
            if (extra != 0) {
                for (i in extra..15) {
                    cMac.update(0u)
                }
            }
        }

        //
        // add the text
        //
        cMac.update(data, dataOff, dataLen)
        return cMac.doFinal(macBlock, 0)
    }
}
