package com.oldguy.crypto

import com.oldguy.common.io.Buffer
import com.oldguy.common.io.UByteBuffer

/**
 * implementation of MD5 as outlined in "Handbook of Applied Cryptography", pages 346 - 347.
 */
class MD5Digest : GeneralDigest, EncodableDigest {
    override val algorithmName = "MD5"
    override val digestSize = 16

    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0 // IV's
    private val x = IntArray(16)
    private var xOff = 0

    constructor() {
        reset()
    }

    constructor(encodedState: UByteArray) : super(encodedState) {
        val buf = UByteBuffer(encodedState, Buffer.ByteOrder.BigEndian)
        buf.position = 16
        h1 = buf.int
        h2 = buf.int
        h3 = buf.int
        h4 = buf.int
        xOff = buf.int
        for (i in 0 until xOff) {
            x[i] = buf.int
        }
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    constructor(t: MD5Digest) : super(t) {
        copyIn(t)
    }

    private fun copyIn(t: MD5Digest) {
        super.copyIn(t)
        h1 = t.h1
        h2 = t.h2
        h3 = t.h3
        h4 = t.h4
        t.x.copyInto(x)
        xOff = t.xOff
    }

    override fun processWord(
        bytes: UByteArray,
        inOffset: Int
    ) {
        x[xOff++] = (bytes[inOffset].toInt()
                or (bytes[inOffset + 1].toInt() shl 8)
                or (bytes[inOffset + 2].toInt() shl 16)
                or (bytes[inOffset + 3].toInt() shl 24))
        if (xOff == 16) {
            processBlock()
        }
    }

    override fun processLength(
        bitLength: Long
    ) {
        if (xOff > 14) {
            processBlock()
        }
        x[14] = (bitLength and -0x1).toInt()
        x[15] = (bitLength ushr 32).toInt()
    }

    private fun unpackWord(
        word: Int,
        out: UByteArray,
        outOff: Int
    ) {
        out[outOff] = word.toUByte()
        out[outOff + 1] = (word ushr 8).toUByte()
        out[outOff + 2] = (word ushr 16).toUByte()
        out[outOff + 3] = (word ushr 24).toUByte()
    }

    override fun doFinal(
        out: UByteArray,
        outOff: Int
    ): Int {
        finish()
        unpackWord(h1, out, outOff)
        unpackWord(h2, out, outOff + 4)
        unpackWord(h3, out, outOff + 8)
        unpackWord(h4, out, outOff + 12)
        reset()
        return this.digestSize
    }

    /**
     * reset the chaining variables to the IV values.
     */
    override fun reset() {
        super.reset()
        h1 = 0x67452301
        h2 = -0x10325477
        h3 = -0x67452302
        h4 = 0x10325476
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    /*
     * rotate int x left n bits.
     */
    private fun rotateLeft(
        x: Int,
        n: Int
    ): Int {
        return (x shl n) or (x ushr (32 - n))
    }

    /*
     * F, G, H and I are the basic MD5 functions.
     */
    private fun f(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return (u and v) or (u.inv() and w)
    }

    private fun g(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return (u and w) or (v and w.inv())
    }

    private fun h(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return u xor v xor w
    }

    private fun k(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return v xor (u or w.inv())
    }

    override fun processBlock() {
        var a = h1
        var b = h2
        var c = h3
        var d = h4

        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotateLeft(a + f(b, c, d) + x[0] + -0x28955b88, S11) + b
        d = rotateLeft(d + f(a, b, c) + x[1] + -0x173848aa, S12) + a
        c = rotateLeft(c + f(d, a, b) + x[2] + 0x242070db, S13) + d
        b = rotateLeft(b + f(c, d, a) + x[3] + -0x3e423112, S14) + c
        a = rotateLeft(a + f(b, c, d) + x[4] + -0xa83f051, S11) + b
        d = rotateLeft(d + f(a, b, c) + x[5] + 0x4787c62a, S12) + a
        c = rotateLeft(c + f(d, a, b) + x[6] + -0x57cfb9ed, S13) + d
        b = rotateLeft(b + f(c, d, a) + x[7] + -0x2b96aff, S14) + c
        a = rotateLeft(a + f(b, c, d) + x[8] + 0x698098d8, S11) + b
        d = rotateLeft(d + f(a, b, c) + x[9] + -0x74bb0851, S12) + a
        c = rotateLeft(c + f(d, a, b) + x[10] + -0xa44f, S13) + d
        b = rotateLeft(b + f(c, d, a) + x[11] + -0x76a32842, S14) + c
        a = rotateLeft(a + f(b, c, d) + x[12] + 0x6b901122, S11) + b
        d = rotateLeft(d + f(a, b, c) + x[13] + -0x2678e6d, S12) + a
        c = rotateLeft(c + f(d, a, b) + x[14] + -0x5986bc72, S13) + d
        b = rotateLeft(b + f(c, d, a) + x[15] + 0x49b40821, S14) + c

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + g(b, c, d) + x[1] + -0x9e1da9e, S21) + b
        d = rotateLeft(d + g(a, b, c) + x[6] + -0x3fbf4cc0, S22) + a
        c = rotateLeft(c + g(d, a, b) + x[11] + 0x265e5a51, S23) + d
        b = rotateLeft(b + g(c, d, a) + x[0] + -0x16493856, S24) + c
        a = rotateLeft(a + g(b, c, d) + x[5] + -0x29d0efa3, S21) + b
        d = rotateLeft(d + g(a, b, c) + x[10] + 0x02441453, S22) + a
        c = rotateLeft(c + g(d, a, b) + x[15] + -0x275e197f, S23) + d
        b = rotateLeft(b + g(c, d, a) + x[4] + -0x182c0438, S24) + c
        a = rotateLeft(a + g(b, c, d) + x[9] + 0x21e1cde6, S21) + b
        d = rotateLeft(d + g(a, b, c) + x[14] + -0x3cc8f82a, S22) + a
        c = rotateLeft(c + g(d, a, b) + x[3] + -0xb2af279, S23) + d
        b = rotateLeft(b + g(c, d, a) + x[8] + 0x455a14ed, S24) + c
        a = rotateLeft(a + g(b, c, d) + x[13] + -0x561c16fb, S21) + b
        d = rotateLeft(d + g(a, b, c) + x[2] + -0x3105c08, S22) + a
        c = rotateLeft(c + g(d, a, b) + x[7] + 0x676f02d9, S23) + d
        b = rotateLeft(b + g(c, d, a) + x[12] + -0x72d5b376, S24) + c

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + h(b, c, d) + x[5] + -0x5c6be, S31) + b
        d = rotateLeft(d + h(a, b, c) + x[8] + -0x788e097f, S32) + a
        c = rotateLeft(c + h(d, a, b) + x[11] + 0x6d9d6122, S33) + d
        b = rotateLeft(b + h(c, d, a) + x[14] + -0x21ac7f4, S34) + c
        a = rotateLeft(a + h(b, c, d) + x[1] + -0x5b4115bc, S31) + b
        d = rotateLeft(d + h(a, b, c) + x[4] + 0x4bdecfa9, S32) + a
        c = rotateLeft(c + h(d, a, b) + x[7] + -0x944b4a0, S33) + d
        b = rotateLeft(b + h(c, d, a) + x[10] + -0x41404390, S34) + c
        a = rotateLeft(a + h(b, c, d) + x[13] + 0x289b7ec6, S31) + b
        d = rotateLeft(d + h(a, b, c) + x[0] + -0x155ed806, S32) + a
        c = rotateLeft(c + h(d, a, b) + x[3] + -0x2b10cf7b, S33) + d
        b = rotateLeft(b + h(c, d, a) + x[6] + 0x04881d05, S34) + c
        a = rotateLeft(a + h(b, c, d) + x[9] + -0x262b2fc7, S31) + b
        d = rotateLeft(d + h(a, b, c) + x[12] + -0x1924661b, S32) + a
        c = rotateLeft(c + h(d, a, b) + x[15] + 0x1fa27cf8, S33) + d
        b = rotateLeft(b + h(c, d, a) + x[2] + -0x3b53a99b, S34) + c

        //
        // Round 4 - K cycle, 16 times.
        //
        a = rotateLeft(a + k(b, c, d) + x[0] + -0xbd6ddbc, S41) + b
        d = rotateLeft(d + k(a, b, c) + x[7] + 0x432aff97, S42) + a
        c = rotateLeft(c + k(d, a, b) + x[14] + -0x546bdc59, S43) + d
        b = rotateLeft(b + k(c, d, a) + x[5] + -0x36c5fc7, S44) + c
        a = rotateLeft(a + k(b, c, d) + x[12] + 0x655b59c3, S41) + b
        d = rotateLeft(d + k(a, b, c) + x[3] + -0x70f3336e, S42) + a
        c = rotateLeft(c + k(d, a, b) + x[10] + -0x100b83, S43) + d
        b = rotateLeft(b + k(c, d, a) + x[1] + -0x7a7ba22f, S44) + c
        a = rotateLeft(a + k(b, c, d) + x[8] + 0x6fa87e4f, S41) + b
        d = rotateLeft(d + k(a, b, c) + x[15] + -0x1d31920, S42) + a
        c = rotateLeft(c + k(d, a, b) + x[6] + -0x5cfebcec, S43) + d
        b = rotateLeft(b + k(c, d, a) + x[13] + 0x4e0811a1, S44) + c
        a = rotateLeft(a + k(b, c, d) + x[4] + -0x8ac817e, S41) + b
        d = rotateLeft(d + k(a, b, c) + x[11] + -0x42c50dcb, S42) + a
        c = rotateLeft(c + k(d, a, b) + x[2] + 0x2ad7d2bb, S43) + d
        b = rotateLeft(b + k(c, d, a) + x[9] + -0x14792c6f, S44) + c
        h1 += a
        h2 += b
        h3 += c
        h4 += d

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    override fun copy(): Memoable {
        return MD5Digest(this)
    }

    override fun reset(other: Memoable) {
        val d = other as MD5Digest
        copyIn(d)
    }

    override val encodedState: UByteArray
        get() {
            val state = UByteArray(36 + xOff * 4)
            super.populateState(state)
            val buf = UByteBuffer(state, Buffer.ByteOrder.BigEndian)
            buf.position = 16
            buf.int = h1
            buf.int = h2
            buf.int = h3
            buf.int = h4
            buf.int = xOff
            for (i in 0 until xOff) {
                buf.int = x[i]
            }
            return state
        }

    companion object {
        //
        // round 1 left rotates
        //
        private const val S11 = 7
        private const val S12 = 12
        private const val S13 = 17
        private const val S14 = 22

        //
        // round 2 left rotates
        //
        private const val S21 = 5
        private const val S22 = 9
        private const val S23 = 14
        private const val S24 = 20

        //
        // round 3 left rotates
        //
        private const val S31 = 4
        private const val S32 = 11
        private const val S33 = 16
        private const val S34 = 23

        //
        // round 4 left rotates
        //
        private const val S41 = 6
        private const val S42 = 10
        private const val S43 = 15
        private const val S44 = 21
    }
}

/**
 * implementation of MD4 as RFC 1320 by R. Rivest, MIT Laboratory for
 * Computer Science and RSA Data Security, Inc.
 *
 *
 * **NOTE**: This algorithm is only included for backwards compatability
 * with legacy applications, it's not secure, don't use it for anything new!
 */
class MD4Digest : GeneralDigest {
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0 // IV's
    private val x = IntArray(16)
    private var xOff = 0

    override val digestSize = 16
    override val algorithmName = "MD4"

    /**
     * Standard constructor
     */
    constructor() {
        reset()
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    constructor(t: MD4Digest) : super(t) {
        copyIn(t)
    }

    private fun copyIn(t: MD4Digest) {
        super.copyIn(t)
        h1 = t.h1
        h2 = t.h2
        h3 = t.h3
        h4 = t.h4
        t.x.copyInto(x, 0, 0, t.x.size)
        xOff = t.xOff
    }

    override fun processWord(
        bytes: UByteArray,
        inOffset: Int
    ) {
        x[xOff++] =
            ((bytes[inOffset].toInt() and 0xff) or ((bytes[inOffset + 1].toInt() and 0xff) shl 8)
                    or ((bytes[inOffset + 2].toInt() and 0xff) shl 16) or ((bytes[inOffset + 3].toInt() and 0xff) shl 24))
        if (xOff == 16) {
            processBlock()
        }
    }

    override fun processLength(
        bitLength: Long
    ) {
        if (xOff > 14) {
            processBlock()
        }
        x[14] = (bitLength and -0x1).toInt()
        x[15] = (bitLength ushr 32).toInt()
    }

    private fun unpackWord(
        word: Int,
        out: UByteArray,
        outOff: Int
    ) {
        out[outOff] = word.toUByte()
        out[outOff + 1] = (word ushr 8).toUByte()
        out[outOff + 2] = (word ushr 16).toUByte()
        out[outOff + 3] = (word ushr 24).toUByte()
    }

    override fun doFinal(
        out: UByteArray,
        outOff: Int
    ): Int {
        finish()
        unpackWord(h1, out, outOff)
        unpackWord(h2, out, outOff + 4)
        unpackWord(h3, out, outOff + 8)
        unpackWord(h4, out, outOff + 12)
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables to the IV values.
     */
    override fun reset() {
        super.reset()
        h1 = 0x67452301
        h2 = -0x10325477
        h3 = -0x67452302
        h4 = 0x10325476
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    /*
     * rotate int x left n bits.
     */
    private fun rotateLeft(
        x: Int,
        n: Int
    ): Int {
        return x shl n or (x ushr 32 - n)
    }

    /*
     * F, G, H and I are the basic MD4 functions.
     */
    private fun f(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return u and v or (u.inv() and w)
    }

    private fun g(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return u and v or (u and w) or (v and w)
    }

    private fun h(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return u xor v xor w
    }

    override fun processBlock() {
        var a = h1
        var b = h2
        var c = h3
        var d = h4

        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotateLeft(a + f(b, c, d) + x[0], S11)
        d = rotateLeft(d + f(a, b, c) + x[1], S12)
        c = rotateLeft(c + f(d, a, b) + x[2], S13)
        b = rotateLeft(b + f(c, d, a) + x[3], S14)
        a = rotateLeft(a + f(b, c, d) + x[4], S11)
        d = rotateLeft(d + f(a, b, c) + x[5], S12)
        c = rotateLeft(c + f(d, a, b) + x[6], S13)
        b = rotateLeft(b + f(c, d, a) + x[7], S14)
        a = rotateLeft(a + f(b, c, d) + x[8], S11)
        d = rotateLeft(d + f(a, b, c) + x[9], S12)
        c = rotateLeft(c + f(d, a, b) + x[10], S13)
        b = rotateLeft(b + f(c, d, a) + x[11], S14)
        a = rotateLeft(a + f(b, c, d) + x[12], S11)
        d = rotateLeft(d + f(a, b, c) + x[13], S12)
        c = rotateLeft(c + f(d, a, b) + x[14], S13)
        b = rotateLeft(b + f(c, d, a) + x[15], S14)

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + g(b, c, d) + x[0] + 0x5a827999, S21)
        d = rotateLeft(d + g(a, b, c) + x[4] + 0x5a827999, S22)
        c = rotateLeft(c + g(d, a, b) + x[8] + 0x5a827999, S23)
        b = rotateLeft(b + g(c, d, a) + x[12] + 0x5a827999, S24)
        a = rotateLeft(a + g(b, c, d) + x[1] + 0x5a827999, S21)
        d = rotateLeft(d + g(a, b, c) + x[5] + 0x5a827999, S22)
        c = rotateLeft(c + g(d, a, b) + x[9] + 0x5a827999, S23)
        b = rotateLeft(b + g(c, d, a) + x[13] + 0x5a827999, S24)
        a = rotateLeft(a + g(b, c, d) + x[2] + 0x5a827999, S21)
        d = rotateLeft(d + g(a, b, c) + x[6] + 0x5a827999, S22)
        c = rotateLeft(c + g(d, a, b) + x[10] + 0x5a827999, S23)
        b = rotateLeft(b + g(c, d, a) + x[14] + 0x5a827999, S24)
        a = rotateLeft(a + g(b, c, d) + x[3] + 0x5a827999, S21)
        d = rotateLeft(d + g(a, b, c) + x[7] + 0x5a827999, S22)
        c = rotateLeft(c + g(d, a, b) + x[11] + 0x5a827999, S23)
        b = rotateLeft(b + g(c, d, a) + x[15] + 0x5a827999, S24)

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + h(b, c, d) + x[0] + 0x6ed9eba1, S31)
        d = rotateLeft(d + h(a, b, c) + x[8] + 0x6ed9eba1, S32)
        c = rotateLeft(c + h(d, a, b) + x[4] + 0x6ed9eba1, S33)
        b = rotateLeft(b + h(c, d, a) + x[12] + 0x6ed9eba1, S34)
        a = rotateLeft(a + h(b, c, d) + x[2] + 0x6ed9eba1, S31)
        d = rotateLeft(d + h(a, b, c) + x[10] + 0x6ed9eba1, S32)
        c = rotateLeft(c + h(d, a, b) + x[6] + 0x6ed9eba1, S33)
        b = rotateLeft(b + h(c, d, a) + x[14] + 0x6ed9eba1, S34)
        a = rotateLeft(a + h(b, c, d) + x[1] + 0x6ed9eba1, S31)
        d = rotateLeft(d + h(a, b, c) + x[9] + 0x6ed9eba1, S32)
        c = rotateLeft(c + h(d, a, b) + x[5] + 0x6ed9eba1, S33)
        b = rotateLeft(b + h(c, d, a) + x[13] + 0x6ed9eba1, S34)
        a = rotateLeft(a + h(b, c, d) + x[3] + 0x6ed9eba1, S31)
        d = rotateLeft(d + h(a, b, c) + x[11] + 0x6ed9eba1, S32)
        c = rotateLeft(c + h(d, a, b) + x[7] + 0x6ed9eba1, S33)
        b = rotateLeft(b + h(c, d, a) + x[15] + 0x6ed9eba1, S34)
        h1 += a
        h2 += b
        h3 += c
        h4 += d

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    override fun copy(): Memoable {
        return MD4Digest(this)
    }

    override fun reset(other: Memoable) {
        val d = other as MD4Digest
        copyIn(d)
    }

    companion object {
        //
        // round 1 left rotates
        //
        private const val S11 = 3
        private const val S12 = 7
        private const val S13 = 11
        private const val S14 = 19

        //
        // round 2 left rotates
        //
        private const val S21 = 3
        private const val S22 = 5
        private const val S23 = 9
        private const val S24 = 13

        //
        // round 3 left rotates
        //
        private const val S31 = 3
        private const val S32 = 9
        private const val S33 = 11
        private const val S34 = 15
    }
}

/**
 * implementation of MD2
 * as outlined in RFC1319 by B.Kaliski from RSA Laboratories April 1992
 */
class MD2Digest : ExtendedDigest, Memoable {
    override val algorithmName = "MD2"
    override val digestSize = 16
    override val byteLength = 16

    /* X buffer */
    private val x = UByteArray(48)
    private var xOff = 0

    /* M buffer */
    private val m = UByteArray(16)
    private var mOff = 0

    /* check sum */
    private val c = UByteArray(16)
    private var cOff = 0

    constructor() {
        reset()
    }

    constructor(t: MD2Digest) {
        copyIn(t)
    }

    private fun copyIn(t: MD2Digest) {
        t.x.copyInto(x)
        xOff = t.xOff
        t.m.copyInto(m)
        mOff = t.mOff
        t.c.copyInto(c)
        cOff = t.cOff
    }

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     *
     * @param out the array the digest is to be copied into.
     * @param outOff the offset into the out array the digest is to start at.
     */
    override fun doFinal(out: UByteArray, outOff: Int): Int {
        // add padding
        val paddingByte = (m.size - mOff).toUByte()
        for (i in mOff until m.size) {
            m[i] = paddingByte
        }
        // do final check sum
        processCheckSum(m)
        // do final block process
        processBlock(m)
        processBlock(c)
        x.copyInto(out, outOff, xOff, xOff + 16)
        reset()
        return digestSize
    }

    /**
     * reset the digest back to it's initial state.
     */
    override fun reset() {
        xOff = 0
        for (i in x.indices) {
            x[i] = 0u
        }
        mOff = 0
        for (i in m.indices) {
            m[i] = 0u
        }
        cOff = 0
        for (i in c.indices) {
            c[i] = 0u
        }
    }

    /**
     * update the message digest with a single byte.
     *
     * @param bytes the input byte to be entered.
     */
    override fun update(bytes: UByte) {
        m[mOff++] = bytes
        if (mOff == 16) {
            processCheckSum(m)
            processBlock(m)
            mOff = 0
        }
    }

    /**
     * update the message digest with a block of bytes.
     *
     * @param bytes the byte array containing the data.
     * @param inOffset the offset into the byte array where the data starts.
     * @param length the length of the data.
     */
    override fun update(bytes: UByteArray, inOffset: Int, length: Int) {
        //
        // fill the current word
        //
        var inOff = inOffset
        var len = length
        while (mOff != 0 && len > 0) {
            update(bytes[inOff])
            inOff++
            len--
        }

        //
        // process whole words.
        //
        while (len > 16) {
            bytes.copyInto(m, 0, inOff, inOff + 16)
            processCheckSum(m)
            processBlock(m)
            len -= 16
            inOff += 16
        }

        //
        // load in the remainder.
        //
        while (len > 0) {
            update(bytes[inOff])
            inOff++
            len--
        }
    }

    private fun processCheckSum(m: UByteArray) {
        var l = c[15].toInt()
        for (i in 0..15) {
            c[i] = c[i] xor s[m[i].toInt() xor (l and 0xff)]
            l = c[i].toInt()
        }
    }

    private fun processBlock(m: UByteArray) {
        for (i in 0..15) {
            x[i + 16] = m[i]
            x[i + 32] = (m[i] xor x[i])
        }
        // encrypt block
        var t = 0
        for (j in 0..17) {
            for (k in 0..47) {
                x[k] = x[k] xor s[t]
                t = x[k].toInt()
                t = t and 0xff
            }
            t = (t + j) % 256
        }
    }

    override fun copy(): Memoable {
        return MD2Digest(this)
    }

    override fun reset(other: Memoable) {
        val d = other as MD2Digest
        copyIn(d)
    }

    companion object {
        // 256-byte random permutation constructed from the digits of PI
        private val s = ubyteArrayOf(
            41u,
            46u,
            67u,
            201u,
            162u,
            216u,
            124u,
            1u,
            61u,
            54u,
            84u,
            161u,
            236u,
            240u,
            6u,
            19u,
            98u,
            167u,
            5u,
            243u,
            192u,
            199u,
            115u,
            140u,
            152u,
            147u,
            43u,
            217u,
            188u,
            76u,
            130u,
            202u,
            30u,
            155u,
            87u,
            60u,
            253u,
            212u,
            224u,
            22u,
            103u,
            66u,
            111u,
            24u,
            138u,
            23u,
            229u,
            18u,
            190u,
            78u,
            196u,
            214u,
            218u,
            158u,
            222u,
            73u,
            160u,
            251u,
            245u,
            142u,
            187u,
            47u,
            238u,
            122u,
            169u,
            104u,
            121u,
            145u,
            21u,
            178u,
            7u,
            63u,
            148u,
            194u,
            16u,
            137u,
            11u,
            34u,
            95u,
            33u,
            128u,
            127u,
            93u,
            154u,
            90u,
            144u,
            50u,
            39u,
            53u,
            62u,
            204u,
            231u,
            191u,
            247u,
            151u,
            3u,
            255u,
            25u,
            48u,
            179u,
            72u,
            165u,
            181u,
            209u,
            215u,
            94u,
            146u,
            42u,
            172u,
            86u,
            170u,
            198u,
            79u,
            184u,
            56u,
            210u,
            150u,
            164u,
            125u,
            182u,
            118u,
            252u,
            107u,
            226u,
            156u,
            116u,
            4u,
            241u,
            69u,
            157u,
            112u,
            89u,
            100u,
            113u,
            135u,
            32u,
            134u,
            91u,
            207u,
            101u,
            230u,
            45u,
            168u,
            2u,
            27u,
            96u,
            37u,
            173u,
            174u,
            176u,
            185u,
            246u,
            28u,
            70u,
            97u,
            105u,
            52u,
            64u,
            126u,
            15u,
            85u,
            71u,
            163u,
            35u,
            221u,
            81u,
            175u,
            58u,
            195u,
            92u,
            249u,
            206u,
            186u,
            197u,
            234u,
            38u,
            44u,
            83u,
            13u,
            110u,
            133u,
            40u,
            132u,
            9u,
            211u,
            223u,
            205u,
            244u,
            65u,
            129u,
            77u,
            82u,
            106u,
            220u,
            55u,
            200u,
            108u,
            193u,
            171u,
            250u,
            36u,
            225u,
            123u,
            8u,
            12u,
            189u,
            177u,
            74u,
            120u,
            136u,
            149u,
            139u,
            227u,
            99u,
            232u,
            109u,
            233u,
            203u,
            213u,
            254u,
            59u,
            0u,
            29u,
            57u,
            242u,
            239u,
            183u,
            14u,
            102u,
            88u,
            208u,
            228u,
            166u,
            119u,
            114u,
            248u,
            235u,
            117u,
            75u,
            10u,
            49u,
            68u,
            80u,
            180u,
            143u,
            237u,
            31u,
            26u, 219u, 153u, 141u, 51u,
            159u, 17u, 131u, 20u
        )
    }
}
