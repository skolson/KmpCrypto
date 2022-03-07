package com.oldguy.crypto

import com.oldguy.common.toLongShl

/**
 * Implementation of WhirlpoolDigest, based on Java source published by Barreto
 * and Rijmen.
 *
 */
class WhirlpoolDigest : ExtendedDigest, Memoable {
    private val _rc = LongArray(ROUNDS + 1)
    override val byteLength = 64
    override val digestSize = 512 / 8

    constructor() {
        for (i in 0..255) {
            val v1 = SBOX[i]
            val v2 = maskWithReductionPolynomial(v1 shl 1)
            val v4 = maskWithReductionPolynomial(v2 shl 1)
            val v5 = v4 xor v1
            val v8 = maskWithReductionPolynomial(v4 shl 1)
            val v9 = v8 xor v1
            C0[i] = packIntoLong(v1, v1, v4, v1, v8, v5, v2, v9)
            C1[i] = packIntoLong(v9, v1, v1, v4, v1, v8, v5, v2)
            C2[i] = packIntoLong(v2, v9, v1, v1, v4, v1, v8, v5)
            C3[i] = packIntoLong(v5, v2, v9, v1, v1, v4, v1, v8)
            C4[i] = packIntoLong(v8, v5, v2, v9, v1, v1, v4, v1)
            C5[i] = packIntoLong(v1, v8, v5, v2, v9, v1, v1, v4)
            C6[i] = packIntoLong(v4, v1, v8, v5, v2, v9, v1, v1)
            C7[i] = packIntoLong(v1, v4, v1, v8, v5, v2, v9, v1)
        }
        _rc[0] = 0L
        for (r in 1..ROUNDS) {
            val i = 8 * (r - 1)
            _rc[r] = C0[i] and -0x100000000000000L xor
                    (C1[i + 1] and 0x00ff000000000000L) xor
                    (C2[i + 2] and 0x0000ff0000000000L) xor
                    (C3[i + 3] and 0x000000ff00000000L) xor
                    (C4[i + 4] and 0x00000000ff000000L) xor
                    (C5[i + 5] and 0x0000000000ff0000L) xor
                    (C6[i + 6] and 0x000000000000ff00L) xor
                    (C7[i + 7] and 0x00000000000000ffL)
        }
    }

    private fun packIntoLong(
        b7: Int,
        b6: Int,
        b5: Int,
        b4: Int,
        b3: Int,
        b2: Int,
        b1: Int,
        b0: Int
    ): Long {
        return b7.toLong() shl 56 xor
                (b6.toLong() shl 48) xor
                (b5.toLong() shl 40) xor
                (b4.toLong() shl 32) xor
                (b3.toLong() shl 24) xor
                (b2.toLong() shl 16) xor
                (b1.toLong() shl 8) xor
                b0.toLong()
    }

    /*
     * int's are used to prevent sign extension.  The values that are really being used are
     * actually just 0..255
     */
    private fun maskWithReductionPolynomial(input: Int): Int {
        var rv = input
        if (rv >= 0x100L) // high bit set
        {
            rv = rv xor REDUCTION_POLYNOMIAL // reduced by the polynomial
        }
        return rv
    }

    private val _buffer = UByteArray(64)
    private var _bufferPos = 0
    private val _bitCount = ShortArray(BITCOUNT_ARRAY_SIZE)

    // -- internal hash state --
    private val _hash = LongArray(8)
    private val _k = LongArray(8) // the round key
    private val _l = LongArray(8)
    private val _block = LongArray(8) // mu (buffer)
    private val _state = LongArray(8) // the current "cipher" state

    /**
     * Copy constructor. This will copy the state of the provided message
     * digest.
     */
    constructor(originalDigest: WhirlpoolDigest) {
        reset(originalDigest)
    }

    override val algorithmName = "Whirlpool"

    override fun doFinal(out: UByteArray, outOff: Int): Int {
        // sets out[outOff] .. out[outOff+DIGEST_LENGTH_BYTES]
        finish()
        for (i in 0..7) {
            convertLongToByteArray(_hash[i], out, outOff + (i * 8))
        }
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables
     */
    override fun reset() {
        // set variables to null, blank, whatever
        _bufferPos = 0
        _bitCount.fill(0)
        _buffer.fill(0u)
        _hash.fill(0)
        _k.fill(0)
        _l.fill(0)
        _block.fill(0)
        _state.fill(0)
    }

    // this takes a buffer of information and fills the block
    @Suppress("UNUSED_PARAMETER")
    private fun processFilledBuffer(bytes: UByteArray, inOff: Int) {
        // copies into the block...
        for (i in _state.indices) {
            _block[i] = bytesToLongFromBuffer(_buffer, i * 8)
        }
        processBlock()
        _bufferPos = 0
        _buffer.fill(0u)
    }

    private fun bytesToLongFromBuffer(buffer: UByteArray, startPos: Int): Long {
        return buffer.toLongShl(startPos, 56) or
                buffer.toLongShl(startPos + 1, 48) or
                buffer.toLongShl(startPos + 2, 40) or
                buffer.toLongShl(startPos + 3, 32) or
                buffer.toLongShl(startPos + 4, 24) or
                buffer.toLongShl(startPos + 5, 16) or
                buffer.toLongShl(startPos + 6, 8) or
                buffer.toLongShl(startPos + 7)
    }

    private fun convertLongToByteArray(inputLong: Long, outputArray: UByteArray, offSet: Int) {
        for (i in 0..7) {
            outputArray[offSet + i] = ((inputLong shr (56 - (i * 8))) and 0xff).toUByte()
            // (byte)((inputLong >> (56 - (i * 8))) & 0xff)
        }
    }

    private fun processBlock() {
        // buffer contents have been transferred to the _block[] array via
        // processFilledBuffer

        // compute and apply K^0
        for (i in 0..7) {
            _state[i] = _block[i] xor _hash[i].also { _k[i] = it }
        }

        // iterate over the rounds
        for (round in 1..ROUNDS) {
            for (i in 0..7) {
                _l[i] = 0
                _l[i] = _l[i] xor C0[(_k[i - 0 and 7] ushr 56).toInt() and 0xff]
                _l[i] = _l[i] xor C1[(_k[i - 1 and 7] ushr 48).toInt() and 0xff]
                _l[i] = _l[i] xor C2[(_k[i - 2 and 7] ushr 40).toInt() and 0xff]
                _l[i] = _l[i] xor C3[(_k[i - 3 and 7] ushr 32).toInt() and 0xff]
                _l[i] = _l[i] xor C4[(_k[i - 4 and 7] ushr 24).toInt() and 0xff]
                _l[i] = _l[i] xor C5[(_k[i - 5 and 7] ushr 16).toInt() and 0xff]
                _l[i] = _l[i] xor C6[(_k[i - 6 and 7] ushr 8).toInt() and 0xff]
                _l[i] = _l[i] xor C7[_k[i - 7 and 7].toInt() and 0xff]
            }
            _l.copyInto(_k, 0, 0, _k.size)
            _k[0] = _k[0] xor _rc[round]

            // apply the round transformation
            for (i in 0..7) {
                _l[i] = _k[i]
                _l[i] = _l[i] xor C0[(_state[i - 0 and 7] ushr 56).toInt() and 0xff]
                _l[i] = _l[i] xor C1[(_state[i - 1 and 7] ushr 48).toInt() and 0xff]
                _l[i] = _l[i] xor C2[(_state[i - 2 and 7] ushr 40).toInt() and 0xff]
                _l[i] = _l[i] xor C3[(_state[i - 3 and 7] ushr 32).toInt() and 0xff]
                _l[i] = _l[i] xor C4[(_state[i - 4 and 7] ushr 24).toInt() and 0xff]
                _l[i] = _l[i] xor C5[(_state[i - 5 and 7] ushr 16).toInt() and 0xff]
                _l[i] = _l[i] xor C6[(_state[i - 6 and 7] ushr 8).toInt() and 0xff]
                _l[i] = _l[i] xor C7[_state[i - 7 and 7].toInt() and 0xff]
            }

            // save the current state
            _l.copyInto(_state, 0, 0, _state.size)
        }

        // apply Miuaguchi-Preneel compression
        for (i in 0..7) {
            _hash[i] = _hash[i] xor (_state[i] xor _block[i])
        }
    }

    override fun update(bytes: UByte) {
        _buffer[_bufferPos] = bytes

        // System.out.println("adding to buffer = "+_buffer[_bufferPos]);
        ++_bufferPos
        if (_bufferPos == _buffer.size) {
            processFilledBuffer(_buffer, 0)
        }
        increment()
    }

    companion object {
        private const val ROUNDS = 10
        private const val REDUCTION_POLYNOMIAL = 0x011d // 2^8 + 2^4 + 2^3 + 2 + 1;
        private val SBOX = intArrayOf(
            0x18,
            0x23,
            0xc6,
            0xe8,
            0x87,
            0xb8,
            0x01,
            0x4f,
            0x36,
            0xa6,
            0xd2,
            0xf5,
            0x79,
            0x6f,
            0x91,
            0x52,
            0x60,
            0xbc,
            0x9b,
            0x8e,
            0xa3,
            0x0c,
            0x7b,
            0x35,
            0x1d,
            0xe0,
            0xd7,
            0xc2,
            0x2e,
            0x4b,
            0xfe,
            0x57,
            0x15,
            0x77,
            0x37,
            0xe5,
            0x9f,
            0xf0,
            0x4a,
            0xda,
            0x58,
            0xc9,
            0x29,
            0x0a,
            0xb1,
            0xa0,
            0x6b,
            0x85,
            0xbd,
            0x5d,
            0x10,
            0xf4,
            0xcb,
            0x3e,
            0x05,
            0x67,
            0xe4,
            0x27,
            0x41,
            0x8b,
            0xa7,
            0x7d,
            0x95,
            0xd8,
            0xfb,
            0xee,
            0x7c,
            0x66,
            0xdd,
            0x17,
            0x47,
            0x9e,
            0xca,
            0x2d,
            0xbf,
            0x07,
            0xad,
            0x5a,
            0x83,
            0x33,
            0x63,
            0x02,
            0xaa,
            0x71,
            0xc8,
            0x19,
            0x49,
            0xd9,
            0xf2,
            0xe3,
            0x5b,
            0x88,
            0x9a,
            0x26,
            0x32,
            0xb0,
            0xe9,
            0x0f,
            0xd5,
            0x80,
            0xbe,
            0xcd,
            0x34,
            0x48,
            0xff,
            0x7a,
            0x90,
            0x5f,
            0x20,
            0x68,
            0x1a,
            0xae,
            0xb4,
            0x54,
            0x93,
            0x22,
            0x64,
            0xf1,
            0x73,
            0x12,
            0x40,
            0x08,
            0xc3,
            0xec,
            0xdb,
            0xa1,
            0x8d,
            0x3d,
            0x97,
            0x00,
            0xcf,
            0x2b,
            0x76,
            0x82,
            0xd6,
            0x1b,
            0xb5,
            0xaf,
            0x6a,
            0x50,
            0x45,
            0xf3,
            0x30,
            0xef,
            0x3f,
            0x55,
            0xa2,
            0xea,
            0x65,
            0xba,
            0x2f,
            0xc0,
            0xde,
            0x1c,
            0xfd,
            0x4d,
            0x92,
            0x75,
            0x06,
            0x8a,
            0xb2,
            0xe6,
            0x0e,
            0x1f,
            0x62,
            0xd4,
            0xa8,
            0x96,
            0xf9,
            0xc5,
            0x25,
            0x59,
            0x84,
            0x72,
            0x39,
            0x4c,
            0x5e,
            0x78,
            0x38,
            0x8c,
            0xd1,
            0xa5,
            0xe2,
            0x61,
            0xb3,
            0x21,
            0x9c,
            0x1e,
            0x43,
            0xc7,
            0xfc,
            0x04,
            0x51,
            0x99,
            0x6d,
            0x0d,
            0xfa,
            0xdf,
            0x7e,
            0x24,
            0x3b,
            0xab,
            0xce,
            0x11,
            0x8f,
            0x4e,
            0xb7,
            0xeb,
            0x3c,
            0x81,
            0x94,
            0xf7,
            0xb9,
            0x13,
            0x2c,
            0xd3,
            0xe7,
            0x6e,
            0xc4,
            0x03,
            0x56,
            0x44,
            0x7f,
            0xa9,
            0x2a,
            0xbb,
            0xc1,
            0x53,
            0xdc,
            0x0b,
            0x9d,
            0x6c,
            0x31,
            0x74,
            0xf6,
            0x46,
            0xac,
            0x89,
            0x14,
            0xe1,
            0x16,
            0x3a,
            0x69,
            0x09,
            0x70,
            0xb6,
            0xd0,
            0xed,
            0xcc,
            0x42,
            0x98,
            0xa4,
            0x28,
            0x5c,
            0xf8,
            0x86
        )
        private val C0 = LongArray(256)
        private val C1 = LongArray(256)
        private val C2 = LongArray(256)
        private val C3 = LongArray(256)
        private val C4 = LongArray(256)
        private val C5 = LongArray(256)
        private val C6 = LongArray(256)
        private val C7 = LongArray(256)

        // --------------------------------------------------------------------------------------//
        // -- buffer information --
        private const val BITCOUNT_ARRAY_SIZE = 32

        /*
     * increment() can be implemented in this way using 2 arrays or
     * by having some temporary variables that are used to set the
     * value provided by EIGHT[i] and carry within the loop.
     *
     * not having done any timing, this seems likely to be faster
     * at the slight expense of 32*(sizeof short) bytes
     */
        private val EIGHT = ShortArray(BITCOUNT_ARRAY_SIZE)

        init {
            EIGHT[BITCOUNT_ARRAY_SIZE - 1] = 8
        }
    }

    private fun increment() {
        var carry = 0
        for (i in _bitCount.indices.reversed()) {
            val sum: Int = (_bitCount[i].toInt() and 0xff) + EIGHT[i] + carry
            carry = sum ushr 8
            _bitCount[i] = (sum and 0xff).toShort()
        }
    }

    override fun update(bytes: UByteArray, inOffset: Int, length: Int) {
        var inOff = inOffset
        var len = length
        while (len > 0) {
            update(bytes[inOff])
            ++inOff
            --len
        }
    }

    private fun finish() {
        /*
         * this makes a copy of the current bit length. at the expense of an
         * object creation of 32 bytes rather than providing a _stopCounting
         * boolean which was the alternative I could think of.
         */
        val bitLength = copyBitLength()
        _buffer[_bufferPos++] = _buffer[_bufferPos++] or 0x80u
        if (_bufferPos == _buffer.size) {
            processFilledBuffer(_buffer, 0)
        }

        /*
         * Final block contains
         * [ ... data .... ][0][0][0][ length ]
         *
         * if [ length ] cannot fit.  Need to create a new block.
         */if (_bufferPos > 32) {
            while (_bufferPos != 0) {
                update(0u)
            }
        }
        while (_bufferPos <= 32) {
            update(0u)
        }

        // copy the length information to the final 32 bytes of the
        // 64 byte block....
        bitLength.copyInto(_buffer, 32, 0, bitLength.size)
        processFilledBuffer(_buffer, 0)
    }

    private fun copyBitLength(): UByteArray {
        val rv = UByteArray(BITCOUNT_ARRAY_SIZE)
        for (i in rv.indices) {
            rv[i] = (_bitCount[i].toInt() and 0xff).toUByte()
        }
        return rv
    }

    override fun copy(): Memoable {
        return WhirlpoolDigest(this)
    }

    override fun reset(other: Memoable) {
        val originalDigest = other as WhirlpoolDigest
        originalDigest._rc.copyInto(_rc, 0, 0, _rc.size)
        originalDigest._buffer.copyInto(_buffer, 0, 0, _buffer.size)
        _bufferPos = originalDigest._bufferPos
        originalDigest._bitCount.copyInto(_bitCount, 0, 0, _bitCount.size)

        // -- internal hash state --
        originalDigest._hash.copyInto(_hash, 0, 0, _hash.size)
        originalDigest._k.copyInto(_k, 0, 0, _k.size)
        originalDigest._l.copyInto(_l, 0, 0, _l.size)
        originalDigest._block.copyInto(_block, 0, 0, _block.size)
        originalDigest._state.copyInto(_state, 0, 0, _state.size)
    }
}
