package com.oldguy.crypto

import com.oldguy.common.getLongAt
import com.oldguy.common.toPosInt

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple
 * block cipher. This mode is also known as CTR mode.
 */
class SICBlockCipher(override val cipher: BlockCipher) : StreamBlockCipher(cipher),
    SkippingStreamCipher {
    override val blockSize = cipher.blockSize
    override val ivSize = blockSize
    override val algorithmName = "${cipher.algorithmName}/SIC"
    private var initVector = UByteArray(blockSize)
    private val counter = UByteArray(blockSize)
    private val counterOut = UByteArray(blockSize)
    private var byteCount = 0

    override fun init(forEncryption: Boolean, params: CipherParameters) {
        if (params is ParametersWithIV) {
            initVector = params.iV.copyOf()
            if (blockSize < initVector.size) {
                throw IllegalArgumentException("CTR/SIC mode requires IV no greater than: $blockSize bytes.")
            }
            val maxCounterSize = if (8 > blockSize / 2) blockSize / 2 else 8
            if (blockSize - initVector.size > maxCounterSize) {
                throw IllegalArgumentException("CTR/SIC mode requires IV of at least: ${blockSize - maxCounterSize} bytes.")
            }
            cipher.init(true, params)
            reset()
        } else {
            throw IllegalArgumentException("CTR/SIC mode requires ParametersWithIV")
        }
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        processBytes(inBlock, inOff, blockSize, outBlock, outOff)
        return blockSize
    }

    override fun processStreamBytes(
        bytes: UByteArray,
        inOff: Int,
        len: Int,
        out: UByteArray,
        outOff: Int
    ): Int {
        processBytes(bytes, inOff, blockSize, out, outOff)
        return blockSize
    }

    override fun calculateByte(b: UByte): UByte {
        if (byteCount == 0) {
            cipher.processBlock(counter, 0, counterOut, 0)
            return counterOut[byteCount++] xor b
        }
        val rv = counterOut[byteCount++] xor b
        if (byteCount == counter.size) {
            byteCount = 0
            incrementCounterAt(0)
            checkCounter()
        }
        return rv
    }

    private fun checkCounter() {
        // if the IV is the same as the blocksize we assume the user knows what they are doing
        if (initVector.size < blockSize) {
            for (i in initVector.indices) {
                if (counter[i] != initVector[i]) {
                    throw IllegalStateException("Counter in CTR/SIC mode out of range.")
                }
            }
        }
    }

    private fun incrementCounterAt(pos: Int) {
        var i = counter.size - pos
        while (--i >= 0) {
            if ((++counter[i]) != 0.toUByte()) {
                break
            }
        }
    }

    private fun incrementCounter(offSet: Int) {
        val old = counter[counter.size - 1]
        counter[counter.size - 1] =
            ((counter[counter.size - 1].toInt() + offSet) and 0xff).toUByte()
        if (old.toInt() != 0 && counter[counter.size - 1] < old) {
            incrementCounterAt(1)
        }
    }

    private fun decrementCounterAt(pos: Int) {
        var i = counter.size - pos
        while (--i >= 0) {
            if ((--counter[i]).toInt() != -1) {
                return
            }
        }
    }

    private fun adjustCounter(n: Long) {
        if (n >= 0) {
            val numBlocks = (n + byteCount) / blockSize
            var rem = numBlocks
            if (rem > 255) {
                for (i in 5 downTo 1) {
                    val diff = 1L shl 8 * i
                    while (rem >= diff) {
                        incrementCounterAt(i)
                        rem -= diff
                    }
                }
            }
            incrementCounter(rem.toInt())
            byteCount = (n + byteCount - blockSize * numBlocks).toInt()
        } else {
            val numBlocks = (-n - byteCount) / blockSize
            var rem = numBlocks
            if (rem > 255) {
                for (i in 5 downTo 1) {
                    val diff = 1L shl 8 * i
                    while (rem > diff) {
                        decrementCounterAt(i)
                        rem -= diff
                    }
                }
            }
            for (i in 0 until rem) {
                decrementCounterAt(0)
            }
            val gap = (byteCount + n + blockSize * numBlocks).toInt()
            byteCount = if (gap >= 0) {
                0
            } else {
                decrementCounterAt(0)
                blockSize + gap
            }
        }
    }

    override fun reset() {
        counter.fill(0u)
        initVector.copyInto(counter)
        cipher.reset()
        byteCount = 0
    }

    override fun skip(numberOfBytes: Long): Long {
        adjustCounter(numberOfBytes)
        checkCounter()
        cipher.processBlock(counter, 0, counterOut, 0)
        return numberOfBytes
    }

    override fun seekTo(position: Long): Long {
        reset()
        return skip(position)
    }

    override val position: Long
        get() {
            val res = UByteArray(counter.size)
            counter.copyInto(res, 0, 0, res.size)
            for (i in res.size - 1 downTo 1) {
                var v = if (i < initVector.size) {
                    res.toPosInt(i) - initVector.toPosInt(i)
                } else {
                    res.toPosInt(i)
                }
                if (v < 0) {
                    res[i - 1]--
                    v += 256
                }
                res[i] = v.toUByte()
            }
            return res.getLongAt(0, false) * blockSize + byteCount
        }
}
