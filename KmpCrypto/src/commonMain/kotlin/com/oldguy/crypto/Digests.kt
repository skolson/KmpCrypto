package com.oldguy.crypto

import com.oldguy.common.io.Buffer
import com.oldguy.common.io.UByteBuffer
import kotlin.math.max

/**
 * interface that a message digest conforms to.
 */
interface Digest {
    /**
     * return the algorithm name
     *
     * @return the algorithm name
     */
    val algorithmName: String

    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    val digestSize: Int

    /**
     * update the message digest with a single byte.
     *
     * @param bytes the input byte to be entered.
     */
    fun update(bytes: UByte)

    /**
     * update the message digest with a block of bytes.
     *
     * @param bytes the byte array containing the data.
     * @param inOffset the offset into the byte array where the data starts.
     * @param length the length of the data.
     */
    fun update(bytes: UByteArray, inOffset: Int, length: Int)

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     *
     * @param out the array the digest is to be copied into.
     * @param outOff the offset into the out array the digest is to start at.
     */
    fun doFinal(out: UByteArray, outOff: Int): Int

    /**
     * reset the digest back to it's initial state.
     */
    fun reset()

    /**
     * Creates a hash from one or optionally two byte arrays.
     * @param bytes1 must not be empty, can be pretty much any length
     * @param bytes2 defaults to empty. If not empty, updates the hash being built from [bytes1]
     * @return byte array containing the result hash
     */
    fun hash(
        bytes1: UByteArray,
        bytes2: UByteArray = UByteArray(0),
        resultLen: Int = 0
    ): UByteArray {
        reset()
        update(bytes1, 0, bytes1.size)
        if (bytes2.isNotEmpty()) {
            update(bytes2, 0, bytes2.size)
        }

        // Get digest value
        var digestBytes = UByteArray(digestSize)
        doFinal(digestBytes, 0)

        // adjust to desired length
        if (resultLen > 0) {
            digestBytes = digestBytes.copyOf(resultLen)
        }
        return digestBytes
    }
}

interface ExtendedDigest : Digest {
    /**
     * Return the size in bytes of the internal buffer the digest applies it's compression
     * function to.
     *
     * @return byte length of the digests internal buffer.
     */
    val byteLength: Int
}

/**
 * Interface for Memoable objects. Memoable objects allow the taking of a snapshot of their internal state
 * via the copy() method and then reseting the object back to that state later using the reset() method.
 */
interface Memoable {
    /**
     * Produce a copy of this object with its configuration and in its current state.
     *
     *
     * The returned object may be used simply to store the state, or may be used as a similar object
     * starting from the copied state.
     */
    fun copy(): Memoable

    /**
     * Restore a copied object state into this object.
     *
     *
     * Implementations of this method *should* try to avoid or minimise memory allocation to perform the reset.
     *
     * @param other an object originally [copied][.copy] from an object of the same type as this instance.
     */
    fun reset(other: Memoable)
}

/**
 * base implementation of MD4 family style digest as outlined in
 * "Handbook of Applied Cryptography", pages 344 - 347.
 */
abstract class GeneralDigest : ExtendedDigest,
    Memoable {
    override val byteLength = 64
    private val xBuf = UByteArray(4)
    private var xBufOff = 0
    private var byteCount: Long = 0

    /**
     * Standard constructor
     */
    protected constructor() {
        xBufOff = 0
    }

    /**
     * Copy constructor.  We are using copy constructors in place
     * of the Object.clone() interface as this interface is not
     * supported by J2ME.
     */
    protected constructor(t: GeneralDigest) {
        copyIn(t)
    }

    protected constructor(encodedState: UByteArray) {
        encodedState.copyInto(xBuf, 0, 0, xBuf.size)
        val buf = UByteBuffer(encodedState, Buffer.ByteOrder.BigEndian)
        buf.position = 4
        xBufOff = buf.int
        byteCount = buf.long
    }

    protected fun copyIn(t: GeneralDigest) {
        t.xBuf.copyInto(xBuf, 0, 0, t.xBuf.size)
        xBufOff = t.xBufOff
        byteCount = t.byteCount
    }

    override fun update(
        bytes: UByte
    ) {
        xBuf[xBufOff++] = bytes
        if (xBufOff == xBuf.size) {
            processWord(xBuf, 0)
            xBufOff = 0
        }
        byteCount++
    }

    override fun update(
        bytes: UByteArray,
        inOffset: Int,
        length: Int
    ) {
        var len = length
        len = max(0, len)

        //
        // fill the current word
        //
        var i = 0
        if (xBufOff != 0) {
            while (i < len) {
                xBuf[xBufOff++] = bytes[inOffset + i++]
                if (xBufOff == 4) {
                    processWord(xBuf, 0)
                    xBufOff = 0
                    break
                }
            }
        }

        //
        // process whole words.
        //
        val limit = (len - i and 3.inv()) + i
        while (i < limit) {
            processWord(bytes, inOffset + i)
            i += 4
        }

        //
        // load in the remainder.
        //
        while (i < len) {
            xBuf[xBufOff++] = bytes[inOffset + i++]
        }
        byteCount += len.toLong()
    }

    fun finish() {
        val bitLength = byteCount shl 3

        //
        // add the pad bytes.
        //
        update(128u)
        while (xBufOff != 0) {
            update(0u)
        }
        processLength(bitLength)
        processBlock()
    }

    override fun reset() {
        byteCount = 0
        xBufOff = 0
        for (i in xBuf.indices) {
            xBuf[i] = 0u
        }
    }

    protected fun populateState(state: UByteArray) {
        xBuf.copyInto(state, 0, xBufOff)
        val buf = UByteBuffer(12, Buffer.ByteOrder.BigEndian)
        buf.int = xBufOff
        buf.long = byteCount
        buf.contentBytes.copyInto(state, 4)
    }

    protected abstract fun processWord(bytes: UByteArray, inOffset: Int)
    protected abstract fun processLength(bitLength: Long)
    protected abstract fun processBlock()
}

/**
 * Encodable digests allow you to download an encoded copy of their internal state. This is useful for the situation where
 * you need to generate a signature on an external device and it allows for "sign with last round", so a copy of the
 * internal state of the digest, plus the last few blocks of the message are all that needs to be sent, rather than the
 * entire message.
 */
interface EncodableDigest {
    /**
     * Return an encoded byte array for the digest's internal state
     *
     * @return an encoding of the digests internal state.
     */
    val encodedState: UByteArray
}

/**
 * implementation of SHA-1 as outlined in "Handbook of Applied Cryptography", pages 346 - 349.
 *
 * It is interesting to ponder why the, apart from the extra IV, the other difference here from MD5
 * is the "endianness" of the word processing!
 */
class SHA1Digest : GeneralDigest,
    EncodableDigest {
    override val digestSize = 20
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0
    private var h5 = 0
    private val x = IntArray(80)
    private var xOff = 0

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
    constructor(t: SHA1Digest) : super(t) {
        copyIn(t)
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    constructor(encodedState: UByteArray) : super(encodedState) {
        val buf = UByteBuffer(encodedState, Buffer.ByteOrder.BigEndian)
        buf.position = 16
        h1 = buf.int
        h2 = buf.int
        h3 = buf.int
        h4 = buf.int
        h5 = buf.int
        xOff = buf.int
        for (i in 0 until xOff) {
            x[i] = buf.int
        }
    }

    private fun copyIn(t: SHA1Digest) {
        h1 = t.h1
        h2 = t.h2
        h3 = t.h3
        h4 = t.h4
        h5 = t.h5
        t.x.copyInto(x)
        xOff = t.xOff
    }

    override val algorithmName = "SHA-1"

    override fun processWord(
        bytes: UByteArray,
        inOffset: Int
    ) {
        // Note: Inlined for performance
//        X[xOff] = Pack.bigEndianToInt(in, inOff);
        var inOff = inOffset
        var n: Int = bytes[inOff].toInt() shl 24
        n = n or ((bytes[++inOff].toInt() and 0xff) shl 16)
        n = n or ((bytes[++inOff].toInt() and 0xff) shl 8)
        n = n or (bytes[++inOff].toInt() and 0xff)
        x[xOff] = n
        if (++xOff == 16) {
            processBlock()
        }
    }

    override fun processLength(
        bitLength: Long
    ) {
        if (xOff > 14) {
            processBlock()
        }
        x[14] = (bitLength ushr 32).toInt()
        x[15] = bitLength.toInt()
    }

    override fun doFinal(
        out: UByteArray,
        outOff: Int
    ): Int {
        finish()
        val buf = UByteBuffer(out.size, Buffer.ByteOrder.BigEndian)
        buf.position = outOff
        buf.int = h1
        buf.int = h2
        buf.int = h3
        buf.int = h4
        buf.int = h5
        buf.contentBytes.copyInto(out, outOff, outOff)
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables
     */
    override fun reset() {
        super.reset()
        h1 = 0x67452301
        h2 = -0x10325477
        h3 = -0x67452302
        h4 = 0x10325476
        h5 = -0x3c2d1e10
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    private fun f(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return (u and v) or (u.inv() and w)
    }

    private fun h(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return u xor v xor w
    }

    private fun g(
        u: Int,
        v: Int,
        w: Int
    ): Int {
        return (u and v) or (u and w) or (v and w)
    }

    override fun processBlock() {
        //
        // expand 16 word block into 80 word block.
        //
        for (i in 16..79) {
            val t = x[i - 3] xor x[i - 8] xor x[i - 14] xor x[i - 16]
            x[i] = (t shl 1) or (t ushr 31)
        }

        //
        // set up working variables.
        //
        var a = h1
        var b = h2
        var c = h3
        var d = h4
        var e = h5

        //
        // round 1
        //
        var idx = 0
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)

            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            e += ((a shl 5) or (a ushr 27)) + f(b, c, d) + x[idx++] + Y1
            b = (b shl 30) or (b ushr 2)

            d += ((e shl 5) or (e ushr 27)) + f(a, b, c) + x[idx++] + Y1
            a = (a shl 30) or (a ushr 2)
            c += ((d shl 5) or (d ushr 27)) + f(e, a, b) + x[idx++] + Y1
            e = (e shl 30) or (e ushr 2)
            b += ((c shl 5) or (c ushr 27)) + f(d, e, a) + x[idx++] + Y1
            d = (d shl 30) or (d ushr 2)
            a += ((b shl 5) or (b ushr 27)) + f(c, d, e) + x[idx++] + Y1
            c = (c shl 30) or (c ushr 2)
        }

        //
        // round 2
        //
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            e += ((a shl 5) or (a ushr 27)) + h(b, c, d) + x[idx++] + Y2
            b = (b shl 30) or (b ushr 2)
            d += ((e shl 5) or (e ushr 27)) + h(a, b, c) + x[idx++] + Y2
            a = (a shl 30) or (a ushr 2)
            c += ((d shl 5) or (d ushr 27)) + h(e, a, b) + x[idx++] + Y2
            e = (e shl 30) or (e ushr 2)
            b += ((c shl 5) or (c ushr 27)) + h(d, e, a) + x[idx++] + Y2
            d = (d shl 30) or (d ushr 2)
            a += ((b shl 5) or (b ushr 27)) + h(c, d, e) + x[idx++] + Y2
            c = (c shl 30) or (c ushr 2)
        }

        //
        // round 3
        //
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            e += ((a shl 5) or (a ushr 27)) + g(b, c, d) + x[idx++] + Y3
            b = (b shl 30) or (b ushr 2)
            d += ((e shl 5) or (e ushr 27)) + g(a, b, c) + x[idx++] + Y3
            a = (a shl 30) or (a ushr 2)
            c += ((d shl 5) or (d ushr 27)) + g(e, a, b) + x[idx++] + Y3
            e = (e shl 30) or (e ushr 2)
            b += ((c shl 5) or (c ushr 27)) + g(d, e, a) + x[idx++] + Y3
            d = (d shl 30) or (d ushr 2)
            a += ((b shl 5) or (b ushr 27)) + g(c, d, e) + x[idx++] + Y3
            c = (c shl 30) or (c ushr 2)
        }

        //
        // round 4
        //
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            e += ((a shl 5) or (a ushr 27)) + h(b, c, d) + x[idx++] + Y4
            b = (b shl 30) or (b ushr 2)
            d += ((e shl 5) or (e ushr 27)) + h(a, b, c) + x[idx++] + Y4
            a = (a shl 30) or (a ushr 2)
            c += ((d shl 5) or (d ushr 27)) + h(e, a, b) + x[idx++] + Y4
            e = (e shl 30) or (e ushr 2)
            b += ((c shl 5) or (c ushr 27)) + h(d, e, a) + x[idx++] + Y4
            d = (d shl 30) or (d ushr 2)
            a += ((b shl 5) or (b ushr 27)) + h(c, d, e) + x[idx++] + Y4
            c = (c shl 30) or (c ushr 2)
        }
        h1 += a
        h2 += b
        h3 += c
        h4 += d
        h5 += e

        //
        // reset start of the buffer.
        //
        xOff = 0
        for (i in 0..15) {
            x[i] = 0
        }
    }

    override fun copy(): Memoable {
        return SHA1Digest(this)
    }

    override fun reset(other: Memoable) {
        val d = other as SHA1Digest
        super.copyIn(d)
        copyIn(d)
    }

    override val encodedState: UByteArray
        get() {
            val state = UByteArray(40 + xOff * 4)
            super.populateState(state)
            val buf = UByteBuffer(state, Buffer.ByteOrder.BigEndian)
            buf.position = 16
            buf.int = h1
            buf.int = h2
            buf.int = h3
            buf.int = h4
            buf.int = h5
            buf.int = xOff
            for (i in 0 until xOff) {
                buf.int = x[i]
            }
            buf.contentBytes.toUByteArray().copyInto(state)
            return state
        }

    companion object {
        //
        // Additive constants
        //
        private const val Y1 = 0x5a827999
        private const val Y2 = 0x6ed9eba1
        private const val Y3 = -0x70e44324
        private const val Y4 = -0x359d3e2a
    }
}

/**
 * FIPS 180-2 implementation of SHA-256.
 *
 * <pre>
 * block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
</pre> *
 */
class SHA256Digest : GeneralDigest, EncodableDigest {
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0
    private var h5 = 0
    private var h6 = 0
    private var h7 = 0
    private var h8 = 0
    private val x = IntArray(64)
    private var xOff = 0

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
    constructor(t: SHA256Digest) : super(t) {
        copyIn(t)
    }

    private fun copyIn(t: SHA256Digest) {
        super.copyIn(t)
        h1 = t.h1
        h2 = t.h2
        h3 = t.h3
        h4 = t.h4
        h5 = t.h5
        h6 = t.h6
        h7 = t.h7
        h8 = t.h8
        t.x.copyInto(x, 0, 0, t.x.size)
        xOff = t.xOff
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    constructor(encodedState: UByteArray) : super(encodedState) {
        val buf = UByteBuffer(encodedState, Buffer.ByteOrder.BigEndian)
        buf.position = 16
        h1 = buf.int
        h2 = buf.int
        h3 = buf.int
        h4 = buf.int
        h5 = buf.int
        h6 = buf.int
        h7 = buf.int
        h8 = buf.int
        xOff = buf.int
        for (i in 0 until xOff) {
            x[i] = buf.int
        }
    }

    override val algorithmName: String
        get() = "SHA-256"
    override val digestSize = 32

    override fun processWord(
        bytes: UByteArray,
        inOffset: Int
    ) {
        // Note: Inlined for performance
//        X[xOff] = Pack.bigEndianToInt(in, inOff);
        var inOff = inOffset
        var n: Int = bytes[inOff].toInt() shl 24
        n = n or ((bytes[++inOff] and 0xffu).toInt() shl 16)
        n = n or ((bytes[++inOff] and 0xffu).toInt() shl 8)
        n = n or (bytes[++inOff] and 0xffu).toInt()
        x[xOff] = n
        if (++xOff == 16) {
            processBlock()
        }
    }

    override fun processLength(
        bitLength: Long
    ) {
        if (xOff > 14) {
            processBlock()
        }
        x[14] = (bitLength ushr 32).toInt()
        x[15] = (bitLength and -0x1).toInt()
    }

    override fun doFinal(
        out: UByteArray,
        outOff: Int
    ): Int {
        finish()
        val buf = UByteBuffer(out, Buffer.ByteOrder.BigEndian)
        buf.position = outOff
        buf.int = h1
        buf.int = h2
        buf.int = h3
        buf.int = h4
        buf.int = h5
        buf.int = h6
        buf.int = h7
        buf.int = h8
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables
     */
    override fun reset() {
        super.reset()

        /* SHA-256 initial hash value
         * The first 32 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        h1 = 0x6a09e667
        h2 = -0x4498517b
        h3 = 0x3c6ef372
        h4 = -0x5ab00ac6
        h5 = 0x510e527f
        h6 = -0x64fa9774
        h7 = 0x1f83d9ab
        h8 = 0x5be0cd19
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    override fun processBlock() {
        //
        // expand 16 word block into 64 word blocks.
        //
        for (t in 16..63) {
            x[t] = theta1(x[t - 2]) + x[t - 7] + theta0(x[t - 15]) + x[t - 16]
        }

        //
        // set up working variables.
        //
        var a = h1
        var b = h2
        var c = h3
        var d = h4
        var e = h5
        var f = h6
        var g = h7
        var h = h8
        var t = 0
        for (i in 0..7) {
            // t = 8 * i
            h += sum1(e) + ch(e, f, g) + k[t] + x[t]
            d += h
            h += sum0(a) + maj(a, b, c)
            ++t

            // t = 8 * i + 1
            g += sum1(d) + ch(d, e, f) + k[t] + x[t]
            c += g
            g += sum0(h) + maj(h, a, b)
            ++t

            // t = 8 * i + 2
            f += sum1(c) + ch(c, d, e) + k[t] + x[t]
            b += f
            f += sum0(g) + maj(g, h, a)
            ++t

            // t = 8 * i + 3
            e += sum1(b) + ch(b, c, d) + k[t] + x[t]
            a += e
            e += sum0(f) + maj(f, g, h)
            ++t

            // t = 8 * i + 4
            d += sum1(a) + ch(a, b, c) + k[t] + x[t]
            h += d
            d += sum0(e) + maj(e, f, g)
            ++t

            // t = 8 * i + 5
            c += sum1(h) + ch(h, a, b) + k[t] + x[t]
            g += c
            c += sum0(d) + maj(d, e, f)
            ++t

            // t = 8 * i + 6
            b += sum1(g) + ch(g, h, a) + k[t] + x[t]
            f += b
            b += sum0(c) + maj(c, d, e)
            ++t

            // t = 8 * i + 7
            a += sum1(f) + ch(f, g, h) + k[t] + x[t]
            e += a
            a += sum0(b) + maj(b, c, d)
            ++t
        }
        h1 += a
        h2 += b
        h3 += c
        h4 += d
        h5 += e
        h6 += f
        h7 += g
        h8 += h

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0
        for (i in 0..15) {
            x[i] = 0
        }
    }

    /* SHA-256 functions */
    private fun ch(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return (x and y) xor (x.inv() and z)
    }

    private fun maj(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return (x and y) xor (x and z) xor (y and z)
    }

    private fun sum0(
        x: Int
    ): Int {
        return (x ushr 2) or (x shl 30) xor ((x ushr 13) or (x shl 19)) xor ((x ushr 22) or (x shl 10))
    }

    private fun sum1(
        x: Int
    ): Int {
        return (x ushr 6) or (x shl 26) xor ((x ushr 11) or (x shl 21)) xor ((x ushr 25) or (x shl 7))
    }

    private fun theta0(
        x: Int
    ): Int {
        return (x ushr 7) or (x shl 25) xor ((x ushr 18) or (x shl 14)) xor (x ushr 3)
    }

    private fun theta1(
        x: Int
    ): Int {
        return (x ushr 17) or (x shl 15) xor ((x ushr 19) or (x shl 13)) xor (x ushr 10)
    }

    override fun copy(): Memoable {
        return SHA256Digest(this)
    }

    override fun reset(other: Memoable) {
        copyIn(other as SHA256Digest)
    }

    override val encodedState: UByteArray
        get() {
            val state = UByteArray(52 + (xOff * 4))
            super.populateState(state)
            val buf = UByteBuffer(state, Buffer.ByteOrder.BigEndian)
            buf.position = 16
            buf.int = h1
            buf.int = h2
            buf.int = h3
            buf.int = h4
            buf.int = h5
            buf.int = h6
            buf.int = h7
            buf.int = h8
            buf.int = xOff
            for (i in 0 until xOff) {
                buf.int = x[i]
            }
            return state
        }

    companion object {
        /* SHA-256 Constants
         * (represent the first 32 bits of the fractional parts of the
         * cube roots of the first sixty-four prime numbers)
         */
        val k = intArrayOf(
            0x428a2f98,
            0x71374491,
            -0x4a3f0431,
            -0x164a245b,
            0x3956c25b,
            0x59f111f1,
            -0x6dc07d5c,
            -0x54e3a12b,
            -0x27f85568,
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            -0x7f214e02,
            -0x6423f959,
            -0x3e640e8c,
            -0x1b64963f,
            -0x1041b87a,
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            -0x67c1aeae,
            -0x57ce3993,
            -0x4ffcd838,
            -0x40a68039,
            -0x391ff40d,
            -0x2a586eb9,
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            -0x7e3d36d2,
            -0x6d8dd37b,
            -0x5d40175f,
            -0x57e599b5,
            -0x3db47490,
            -0x3893ae5d,
            -0x2e6d17e7,
            -0x2966f9dc,
            -0xbf1ca7b,
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            -0x7b3787ec,
            -0x7338fdf8,
            -0x6f410006,
            -0x5baf9315,
            -0x41065c09,
            -0x398e870e
        )
    }
}
