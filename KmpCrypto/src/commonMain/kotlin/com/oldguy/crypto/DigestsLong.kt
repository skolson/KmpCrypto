package com.oldguy.crypto

import com.oldguy.common.io.Buffer
import com.oldguy.common.io.UByteBuffer

/**
 * Base class for SHA-384 and SHA-512.
 */
abstract class LongDigest : ExtendedDigest, Memoable, EncodableDigest {
    private val xBuf = UByteArray(8)
    private var xBufOff = 0
    private var byteCount1: Long = 0
    private var byteCount2: Long = 0
    protected var h1: Long = 0
    protected var h2: Long = 0
    protected var h3: Long = 0
    protected var h4: Long = 0
    protected var h5: Long = 0
    protected var h6: Long = 0
    protected var h7: Long = 0
    protected var h8: Long = 0
    private val w = LongArray(80)
    private var wOff = 0

    /**
     * Constructor for variable length word
     */
    protected constructor() {
        xBufOff = 0
        initialize()
    }

    /**
     * Copy constructor.  We are using copy constructors in place
     * of the Object.clone() interface as this interface is not
     * supported by J2ME.
     */
    protected constructor(t: LongDigest) {
        copyIn(t)
    }

    override val byteLength = 128

    private fun initialize() {
        byteCount1 = 0
        byteCount2 = 0
        xBufOff = 0
        for (i in xBuf.indices) {
            xBuf[i] = 0u
        }
        wOff = 0
        for (i in w.indices) {
            w[i] = 0
        }
    }

    protected fun copyIn(t: LongDigest) {
        t.xBuf.copyInto(xBuf)
        xBufOff = t.xBufOff
        byteCount1 = t.byteCount1
        byteCount2 = t.byteCount2
        h1 = t.h1
        h2 = t.h2
        h3 = t.h3
        h4 = t.h4
        h5 = t.h5
        h6 = t.h6
        h7 = t.h7
        h8 = t.h8
        t.w.copyInto(w)
        wOff = t.wOff
    }

    protected fun populateState(state: UByteArray) {
        xBuf.copyInto(state, 0, 0, xBufOff)
        val buf = UByteBuffer(state, Buffer.ByteOrder.BigEndian)
        buf.position = xBufOff
        buf.int = xBufOff
        buf.long = byteCount1
        buf.long = byteCount2
        buf.long = h1
        buf.long = h2
        buf.long = h3
        buf.long = h4
        buf.long = h5
        buf.long = h6
        buf.long = h7
        buf.long = h8
        buf.int = wOff
        for (i in 0 until wOff) {
            buf.long = w[i]
        }
    }

    protected fun restoreState(encodedState: UByteArray) {
        val buf = UByteBuffer(encodedState, Buffer.ByteOrder.BigEndian)
        buf.position = 8
        xBufOff = buf.int
        encodedState.copyInto(xBuf, 0, 0, xBufOff)
        byteCount1 = buf.long
        byteCount2 = buf.long
        h1 = buf.long
        h2 = buf.long
        h3 = buf.long
        h4 = buf.long
        h5 = buf.long
        h6 = buf.long
        h7 = buf.long
        h8 = buf.long
        wOff = buf.int
        for (i in 0 until wOff) {
            w[i] = buf.long
        }
    }

    protected val encodedStateSize get() = 96 + wOff * 8

    override fun update(
        bytes: UByte
    ) {
        xBuf[xBufOff++] = bytes
        if (xBufOff == xBuf.size) {
            processWord(xBuf, 0)
            xBufOff = 0
        }
        byteCount1++
    }

    override fun update(
        bytes: UByteArray,
        inOffset: Int,
        length: Int
    ) {
        //
        // fill the current word
        //
        var inOff = inOffset
        var len = length
        while (xBufOff != 0 && len > 0) {
            update(bytes[inOff])
            inOff++
            len--
        }

        //
        // process whole words.
        //
        while (len > xBuf.size) {
            processWord(bytes, inOff)
            inOff += xBuf.size
            len -= xBuf.size
            byteCount1 += xBuf.size.toLong()
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

    fun finish() {
        adjustByteCounts()
        val lowBitLength = byteCount1 shl 3
        val hiBitLength = byteCount2

        //
        // add the pad bytes.
        //
        update(128.toUByte())
        while (xBufOff != 0) {
            update(0u)
        }
        processLength(lowBitLength, hiBitLength)
        processBlock()
    }

    override fun reset() {
        initialize()
    }

    private fun processWord(
        bytes: UByteArray,
        inOff: Int
    ) {
        val buf = UByteBuffer(bytes, Buffer.ByteOrder.BigEndian)
        buf.position = inOff
        w[wOff] = buf.long
        if (++wOff == 16) {
            processBlock()
        }
    }

    /**
     * adjust the byte counts so that byteCount2 represents the
     * upper long (less 3 bits) word of the byte count.
     */
    private fun adjustByteCounts() {
        if (byteCount1 > 0x1fffffffffffffffL) {
            byteCount2 += byteCount1 ushr 61
            byteCount1 = byteCount1 and 0x1fffffffffffffffL
        }
    }

    private fun processLength(
        lowW: Long,
        hiW: Long
    ) {
        if (wOff > 14) {
            processBlock()
        }
        w[14] = hiW
        w[15] = lowW
    }

    private fun processBlock() {
        adjustByteCounts()

        //
        // expand 16 word block into 80 word blocks.
        //
        for (t in 16..79) {
            w[t] = sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16]
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
        for (i in 0..9) {
            // t = 8 * i
            h += sum1(e) + ch(e, f, g) + K[t] + w[t++]
            d += h
            h += sum0(a) + maj(a, b, c)

            // t = 8 * i + 1
            g += sum1(d) + ch(d, e, f) + K[t] + w[t++]
            c += g
            g += sum0(h) + maj(h, a, b)

            // t = 8 * i + 2
            f += sum1(c) + ch(c, d, e) + K[t] + w[t++]
            b += f
            f += sum0(g) + maj(g, h, a)

            // t = 8 * i + 3
            e += sum1(b) + ch(b, c, d) + K[t] + w[t++]
            a += e
            e += sum0(f) + maj(f, g, h)

            // t = 8 * i + 4
            d += sum1(a) + ch(a, b, c) + K[t] + w[t++]
            h += d
            d += sum0(e) + maj(e, f, g)

            // t = 8 * i + 5
            c += sum1(h) + ch(h, a, b) + K[t] + w[t++]
            g += c
            c += sum0(d) + maj(d, e, f)

            // t = 8 * i + 6
            b += sum1(g) + ch(g, h, a) + K[t] + w[t++]
            f += b
            b += sum0(c) + maj(c, d, e)

            // t = 8 * i + 7
            a += sum1(f) + ch(f, g, h) + K[t] + w[t++]
            e += a
            a += sum0(b) + maj(b, c, d)
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
        wOff = 0
        for (i in 0..15) {
            w[i] = 0
        }
    }

    /* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
    private fun ch(
        x: Long,
        y: Long,
        z: Long
    ): Long {
        return (x and y) xor (x.inv() and z)
    }

    private fun maj(
        x: Long,
        y: Long,
        z: Long
    ): Long {
        return (x and y) xor (x and z) xor (y and z)
    }

    private fun sum0(
        x: Long
    ): Long {
        return (x shl 36) or (x ushr 28) xor ((x shl 30) or (x ushr 34)) xor ((x shl 25) or (x ushr 39))
    }

    private fun sum1(
        x: Long
    ): Long {
        return (x shl 50) or (x ushr 14) xor ((x shl 46) or (x ushr 18)) xor ((x shl 23) or (x ushr 41))
    }

    private fun sigma0(
        x: Long
    ): Long {
        return (x shl 63) or (x ushr 1) xor ((x shl 56) or (x ushr 8)) xor (x ushr 7)
    }

    private fun sigma1(
        x: Long
    ): Long {
        return (x shl 45) or (x ushr 19) xor ((x shl 3) or (x ushr 61)) xor (x ushr 6)
    }

    companion object {

        /* SHA-384 and SHA-512 Constants
       * (represent the first 64 bits of the fractional parts of the
       * cube roots of the first sixty-four prime numbers)
       */
        val K = longArrayOf(
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, -0x4a3f043013b2c4d1L, -0x164a245a7e762444L,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, -0x6dc07d5b50e6b065L, -0x54e3a12a25927ee8L,
            -0x27f855675cfcfdbeL, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, -0x7f214e01c4e9694fL, -0x6423f958da38edcbL, -0x3e640e8b3096d96cL,
            -0x1b64963e610eb52eL, -0x1041b879c7b0da1dL, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            -0x67c1aead11992055L, -0x57ce3992d24bcdf0L, -0x4ffcd8376704dec1L, -0x40a680384110f11cL,
            -0x391ff40cc257703eL, -0x2a586eb86cf558dbL, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, -0x7e3d36d1b812511aL, -0x6d8dd37aeb7dcac5L,
            -0x5d40175eb30efc9cL, -0x57e599b443bdcfffL, -0x3db4748f2f07686fL, -0x3893ae5cf9ab41d0L,
            -0x2e6d17e62910ade8L, -0x2966f9dbaa9a56f0L, -0xbf1ca7aa88edfd6L, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, -0x7b3787eb5e0f548eL, -0x7338fdf7e59bc614L,
            -0x6f410005dc9ce1d8L, -0x5baf9314217d4217L, -0x41065c084d3986ebL, -0x398e870d1c8dacd5L,
            -0x35d8c13115d99e64L, -0x2e794738de3f3df9L, -0x15258229321f14e2L, -0xa82b08011912e88L,
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
        )
    }
}

/**
 * FIPS 180-2 implementation of SHA-384.
 *
 * <pre>
 * block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
</pre> *
 */
class SHA384Digest : LongDigest {
    /**
     * Standard constructor
     */
    constructor()

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    constructor(t: SHA384Digest) : super(t)

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    constructor(encodedState: UByteArray) {
        restoreState(encodedState)
    }

    override val algorithmName: String
        get() = "SHA-384"
    override val digestSize = 48

    override fun doFinal(
        out: UByteArray,
        outOff: Int
    ): Int {
        finish()
        val buf = UByteBuffer(out, Buffer.ByteOrder.BigEndian)
        buf.position = outOff
        buf.long = h1
        buf.long = h2
        buf.long = h3
        buf.long = h4
        buf.long = h5
        buf.long = h6
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables
     */
    override fun reset() {
        super.reset()

        /* SHA-384 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the 9th through 16th prime numbers
         */
        h1 = -0x344462a23efa6128L
        h2 = 0x629a292a367cd507L
        h3 = -0x6ea6fea5cf8f22e9L
        h4 = 0x152fecd8f70e5939L
        h5 = 0x67332667ffc00b31L
        h6 = -0x714bb57897a7eaefL
        h7 = -0x24f3d1f29b067059L
        h8 = 0x47b5481dbefa4fa4L
    }

    override fun copy(): Memoable {
        return SHA384Digest(this)
    }

    override fun reset(other: Memoable) {
        super.copyIn(other as SHA384Digest)
    }

    override val encodedState: UByteArray
        get() {
            val encoded = UByteArray(encodedStateSize)
            super.populateState(encoded)
            return encoded
        }
}

/**
 * FIPS 180-2 implementation of SHA-512.
 *
 * <pre>
 * block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
</pre> *
 */
class SHA512Digest : LongDigest {
    /**
     * Standard constructor
     */
    constructor()

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    constructor(t: SHA512Digest) : super(t)

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    constructor(encodedState: UByteArray) {
        restoreState(encodedState)
    }

    override val algorithmName: String
        get() = "SHA-512"
    override val digestSize = 64
    override val byteLength = digestSize

    override fun doFinal(
        out: UByteArray,
        outOff: Int
    ): Int {
        finish()
        val buf = UByteBuffer(out, Buffer.ByteOrder.BigEndian)
        buf.position = outOff
        buf.long = h1
        buf.long = h2
        buf.long = h3
        buf.long = h4
        buf.long = h5
        buf.long = h6
        buf.long = h7
        buf.long = h8
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables
     */
    override fun reset() {
        super.reset()

        /* SHA-512 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        h1 = 0x6a09e667f3bcc908L
        h2 = -0x4498517a7b3558c5L
        h3 = 0x3c6ef372fe94f82bL
        h4 = -0x5ab00ac5a0e2c90fL
        h5 = 0x510e527fade682d1L
        h6 = -0x64fa9773d4c193e1L
        h7 = 0x1f83d9abfb41bd6bL
        h8 = 0x5be0cd19137e2179L
    }

    override fun copy(): Memoable {
        return SHA512Digest(this)
    }

    override fun reset(other: Memoable) {
        copyIn(other as SHA512Digest)
    }

    override val encodedState: UByteArray
        get() {
            val encoded = UByteArray(encodedStateSize)
            super.populateState(encoded)
            return encoded
        }
}
