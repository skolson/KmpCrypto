package com.oldguy.crypto

import com.oldguy.common.toIntShl
import com.oldguy.common.toPosInt

/**
 * implementation of RIPEMD128
 */
class RIPEMD128Digest : GeneralDigest {
    override val digestSize = 16
    override val algorithmName = "RIPEMD128"

    private var h0 = 0
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0 // IV's
    private val x = IntArray(16)
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
    constructor(t: RIPEMD128Digest) : super(t) {
        copyIn(t)
    }

    private fun copyIn(t: RIPEMD128Digest) {
        super.copyIn(t)
        h0 = t.h0
        h1 = t.h1
        h2 = t.h2
        h3 = t.h3
        t.x.copyInto(x)
        xOff = t.xOff
    }

    override fun processWord(
        bytes: UByteArray,
        inOffset: Int
    ) {
        x[xOff++] =
            bytes toPosInt inOffset or
                    bytes.toIntShl(inOffset + 1, 8) or
                    bytes.toIntShl(inOffset + 2, 16) or
                    bytes.toIntShl(inOffset + 3, 24)
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
        unpackWord(h0, out, outOff)
        unpackWord(h1, out, outOff + 4)
        unpackWord(h2, out, outOff + 8)
        unpackWord(h3, out, outOff + 12)
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables to the IV values.
     */
    override fun reset() {
        super.reset()
        h0 = 0x67452301
        h1 = -0x10325477
        h2 = -0x67452302
        h3 = 0x10325476
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    /*
     * rotate int x left n bits.
     */
    private fun rl(
        x: Int,
        n: Int
    ): Int {
        return (x shl n) or (x ushr 32 - n)
    }

    /*
     * f1,f2,f3,f4 are the basic RIPEMD128 functions.
     */
    /*
     * F
     */
    private fun f1(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x xor y xor z
    }

    /*
     * G
     */
    private fun f2(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x and y or (x.inv() and z)
    }

    /*
     * H
     */
    private fun f3(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x or y.inv() xor z
    }

    /*
     * I
     */
    private fun f4(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x and z or (y and z.inv())
    }

    private fun fOf1(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f1(b, c, d) + x, s)
    }

    private fun fOf2(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f2(b, c, d) + x + 0x5a827999, s)
    }

    private fun fOf3(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f3(b, c, d) + x + 0x6ed9eba1, s)
    }

    private fun fOf4(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f4(b, c, d) + x + -0x70e44324, s)
    }

    private fun fF1(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f1(b, c, d) + x, s)
    }

    private fun fF2(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f2(b, c, d) + x + 0x6d703ef3, s)
    }

    private fun fF3(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f3(b, c, d) + x + 0x5c4dd124, s)
    }

    private fun fF4(
        a: Int,
        b: Int,
        c: Int,
        d: Int,
        x: Int,
        s: Int
    ): Int {
        return rl(a + f4(b, c, d) + x + 0x50a28be6, s)
    }

    override fun processBlock() {
        var a: Int
        var b: Int
        var c: Int
        var d: Int
        var aa = h0
        a = aa
        var bb = h1
        b = bb
        var cc = h2
        c = cc
        var dd = h3
        d = dd

        //
        // Round 1
        //
        a = fOf1(a, b, c, d, x[0], 11)
        d = fOf1(d, a, b, c, x[1], 14)
        c = fOf1(c, d, a, b, x[2], 15)
        b = fOf1(b, c, d, a, x[3], 12)
        a = fOf1(a, b, c, d, x[4], 5)
        d = fOf1(d, a, b, c, x[5], 8)
        c = fOf1(c, d, a, b, x[6], 7)
        b = fOf1(b, c, d, a, x[7], 9)
        a = fOf1(a, b, c, d, x[8], 11)
        d = fOf1(d, a, b, c, x[9], 13)
        c = fOf1(c, d, a, b, x[10], 14)
        b = fOf1(b, c, d, a, x[11], 15)
        a = fOf1(a, b, c, d, x[12], 6)
        d = fOf1(d, a, b, c, x[13], 7)
        c = fOf1(c, d, a, b, x[14], 9)
        b = fOf1(b, c, d, a, x[15], 8)

        //
        // Round 2
        //
        a = fOf2(a, b, c, d, x[7], 7)
        d = fOf2(d, a, b, c, x[4], 6)
        c = fOf2(c, d, a, b, x[13], 8)
        b = fOf2(b, c, d, a, x[1], 13)
        a = fOf2(a, b, c, d, x[10], 11)
        d = fOf2(d, a, b, c, x[6], 9)
        c = fOf2(c, d, a, b, x[15], 7)
        b = fOf2(b, c, d, a, x[3], 15)
        a = fOf2(a, b, c, d, x[12], 7)
        d = fOf2(d, a, b, c, x[0], 12)
        c = fOf2(c, d, a, b, x[9], 15)
        b = fOf2(b, c, d, a, x[5], 9)
        a = fOf2(a, b, c, d, x[2], 11)
        d = fOf2(d, a, b, c, x[14], 7)
        c = fOf2(c, d, a, b, x[11], 13)
        b = fOf2(b, c, d, a, x[8], 12)

        //
        // Round 3
        //
        a = fOf3(a, b, c, d, x[3], 11)
        d = fOf3(d, a, b, c, x[10], 13)
        c = fOf3(c, d, a, b, x[14], 6)
        b = fOf3(b, c, d, a, x[4], 7)
        a = fOf3(a, b, c, d, x[9], 14)
        d = fOf3(d, a, b, c, x[15], 9)
        c = fOf3(c, d, a, b, x[8], 13)
        b = fOf3(b, c, d, a, x[1], 15)
        a = fOf3(a, b, c, d, x[2], 14)
        d = fOf3(d, a, b, c, x[7], 8)
        c = fOf3(c, d, a, b, x[0], 13)
        b = fOf3(b, c, d, a, x[6], 6)
        a = fOf3(a, b, c, d, x[13], 5)
        d = fOf3(d, a, b, c, x[11], 12)
        c = fOf3(c, d, a, b, x[5], 7)
        b = fOf3(b, c, d, a, x[12], 5)

        //
        // Round 4
        //
        a = fOf4(a, b, c, d, x[1], 11)
        d = fOf4(d, a, b, c, x[9], 12)
        c = fOf4(c, d, a, b, x[11], 14)
        b = fOf4(b, c, d, a, x[10], 15)
        a = fOf4(a, b, c, d, x[0], 14)
        d = fOf4(d, a, b, c, x[8], 15)
        c = fOf4(c, d, a, b, x[12], 9)
        b = fOf4(b, c, d, a, x[4], 8)
        a = fOf4(a, b, c, d, x[13], 9)
        d = fOf4(d, a, b, c, x[3], 14)
        c = fOf4(c, d, a, b, x[7], 5)
        b = fOf4(b, c, d, a, x[15], 6)
        a = fOf4(a, b, c, d, x[14], 8)
        d = fOf4(d, a, b, c, x[5], 6)
        c = fOf4(c, d, a, b, x[6], 5)
        b = fOf4(b, c, d, a, x[2], 12)

        //
        // Parallel round 1
        //
        aa = fF4(aa, bb, cc, dd, x[5], 8)
        dd = fF4(dd, aa, bb, cc, x[14], 9)
        cc = fF4(cc, dd, aa, bb, x[7], 9)
        bb = fF4(bb, cc, dd, aa, x[0], 11)
        aa = fF4(aa, bb, cc, dd, x[9], 13)
        dd = fF4(dd, aa, bb, cc, x[2], 15)
        cc = fF4(cc, dd, aa, bb, x[11], 15)
        bb = fF4(bb, cc, dd, aa, x[4], 5)
        aa = fF4(aa, bb, cc, dd, x[13], 7)
        dd = fF4(dd, aa, bb, cc, x[6], 7)
        cc = fF4(cc, dd, aa, bb, x[15], 8)
        bb = fF4(bb, cc, dd, aa, x[8], 11)
        aa = fF4(aa, bb, cc, dd, x[1], 14)
        dd = fF4(dd, aa, bb, cc, x[10], 14)
        cc = fF4(cc, dd, aa, bb, x[3], 12)
        bb = fF4(bb, cc, dd, aa, x[12], 6)

        //
        // Parallel round 2
        //
        aa = fF3(aa, bb, cc, dd, x[6], 9)
        dd = fF3(dd, aa, bb, cc, x[11], 13)
        cc = fF3(cc, dd, aa, bb, x[3], 15)
        bb = fF3(bb, cc, dd, aa, x[7], 7)
        aa = fF3(aa, bb, cc, dd, x[0], 12)
        dd = fF3(dd, aa, bb, cc, x[13], 8)
        cc = fF3(cc, dd, aa, bb, x[5], 9)
        bb = fF3(bb, cc, dd, aa, x[10], 11)
        aa = fF3(aa, bb, cc, dd, x[14], 7)
        dd = fF3(dd, aa, bb, cc, x[15], 7)
        cc = fF3(cc, dd, aa, bb, x[8], 12)
        bb = fF3(bb, cc, dd, aa, x[12], 7)
        aa = fF3(aa, bb, cc, dd, x[4], 6)
        dd = fF3(dd, aa, bb, cc, x[9], 15)
        cc = fF3(cc, dd, aa, bb, x[1], 13)
        bb = fF3(bb, cc, dd, aa, x[2], 11)

        //
        // Parallel round 3
        //
        aa = fF2(aa, bb, cc, dd, x[15], 9)
        dd = fF2(dd, aa, bb, cc, x[5], 7)
        cc = fF2(cc, dd, aa, bb, x[1], 15)
        bb = fF2(bb, cc, dd, aa, x[3], 11)
        aa = fF2(aa, bb, cc, dd, x[7], 8)
        dd = fF2(dd, aa, bb, cc, x[14], 6)
        cc = fF2(cc, dd, aa, bb, x[6], 6)
        bb = fF2(bb, cc, dd, aa, x[9], 14)
        aa = fF2(aa, bb, cc, dd, x[11], 12)
        dd = fF2(dd, aa, bb, cc, x[8], 13)
        cc = fF2(cc, dd, aa, bb, x[12], 5)
        bb = fF2(bb, cc, dd, aa, x[2], 14)
        aa = fF2(aa, bb, cc, dd, x[10], 13)
        dd = fF2(dd, aa, bb, cc, x[0], 13)
        cc = fF2(cc, dd, aa, bb, x[4], 7)
        bb = fF2(bb, cc, dd, aa, x[13], 5)

        //
        // Parallel round 4
        //
        aa = fF1(aa, bb, cc, dd, x[8], 15)
        dd = fF1(dd, aa, bb, cc, x[6], 5)
        cc = fF1(cc, dd, aa, bb, x[4], 8)
        bb = fF1(bb, cc, dd, aa, x[1], 11)
        aa = fF1(aa, bb, cc, dd, x[3], 14)
        dd = fF1(dd, aa, bb, cc, x[11], 14)
        cc = fF1(cc, dd, aa, bb, x[15], 6)
        bb = fF1(bb, cc, dd, aa, x[0], 14)
        aa = fF1(aa, bb, cc, dd, x[5], 6)
        dd = fF1(dd, aa, bb, cc, x[12], 9)
        cc = fF1(cc, dd, aa, bb, x[2], 12)
        bb = fF1(bb, cc, dd, aa, x[13], 9)
        aa = fF1(aa, bb, cc, dd, x[9], 12)
        dd = fF1(dd, aa, bb, cc, x[7], 5)
        cc = fF1(cc, dd, aa, bb, x[10], 15)
        bb = fF1(bb, cc, dd, aa, x[14], 8)
        dd += c + h1 // final result for H0

        //
        // combine the results
        //
        h1 = h2 + d + aa
        h2 = h3 + a + bb
        h3 = h0 + b + cc
        h0 = dd

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    override fun copy(): Memoable {
        return RIPEMD128Digest(this)
    }

    override fun reset(other: Memoable) {
        copyIn(other as RIPEMD128Digest)
    }
}

/**
 * implementation of RIPEMD see,
 * http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
 */
class RIPEMD160Digest : GeneralDigest {
    override val digestSize = 20
    override val algorithmName = "RIPEMD160"

    private var h0 = 0
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0 // IV's

    private val x = IntArray(16)
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
    constructor(t: RIPEMD160Digest) : super(t) {
        copyIn(t)
    }

    private fun copyIn(t: RIPEMD160Digest) {
        super.copyIn(t)
        h0 = t.h0
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
        x[xOff++] =
            (bytes toPosInt inOffset) or
                    bytes.toIntShl(inOffset + 1, 8) or
                    bytes.toIntShl(inOffset + 2, 16) or
                    bytes.toIntShl(inOffset + 3, 24)
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
        unpackWord(h0, out, outOff)
        unpackWord(h1, out, outOff + 4)
        unpackWord(h2, out, outOff + 8)
        unpackWord(h3, out, outOff + 12)
        unpackWord(h4, out, outOff + 16)
        reset()
        return digestSize
    }

    /**
     * reset the chaining variables to the IV values.
     */
    override fun reset() {
        super.reset()
        h0 = 0x67452301
        h1 = -0x10325477
        h2 = -0x67452302
        h3 = 0x10325476
        h4 = -0x3c2d1e10
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    /*
     * rotate int x left n bits.
     */
    private fun rl(
        x: Int,
        n: Int
    ): Int {
        return x shl n or (x ushr 32 - n)
    }

    /*
     * f1,f2,f3,f4,f5 are the basic RIPEMD160 functions.
     */
    /*
     * rounds 0-15
     */
    private fun f1(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x xor y xor z
    }

    /*
     * rounds 16-31
     */
    private fun f2(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x and y or (x.inv() and z)
    }

    /*
     * rounds 32-47
     */
    private fun f3(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x or y.inv() xor z
    }

    /*
     * rounds 48-63
     */
    private fun f4(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x and z or (y and z.inv())
    }

    /*
     * rounds 64-79
     */
    private fun f5(
        x: Int,
        y: Int,
        z: Int
    ): Int {
        return x xor (y or z.inv())
    }

    override fun processBlock() {
        var a: Int
        var b: Int
        var c: Int
        var d: Int
        var e: Int
        var aa = h0
        a = aa
        var bb = h1
        b = bb
        var cc = h2
        c = cc
        var dd = h3
        d = dd
        var ee = h4
        e = ee

        //
        // Rounds 1 - 16
        //
        // left
        a = rl(a + f1(b, c, d) + x[0], 11) + e
        c = rl(c, 10)
        e = rl(e + f1(a, b, c) + x[1], 14) + d
        b = rl(b, 10)
        d = rl(d + f1(e, a, b) + x[2], 15) + c
        a = rl(a, 10)
        c = rl(c + f1(d, e, a) + x[3], 12) + b
        e = rl(e, 10)
        b = rl(b + f1(c, d, e) + x[4], 5) + a
        d = rl(d, 10)
        a = rl(a + f1(b, c, d) + x[5], 8) + e
        c = rl(c, 10)
        e = rl(e + f1(a, b, c) + x[6], 7) + d
        b = rl(b, 10)
        d = rl(d + f1(e, a, b) + x[7], 9) + c
        a = rl(a, 10)
        c = rl(c + f1(d, e, a) + x[8], 11) + b
        e = rl(e, 10)
        b = rl(b + f1(c, d, e) + x[9], 13) + a
        d = rl(d, 10)
        a = rl(a + f1(b, c, d) + x[10], 14) + e
        c = rl(c, 10)
        e = rl(e + f1(a, b, c) + x[11], 15) + d
        b = rl(b, 10)
        d = rl(d + f1(e, a, b) + x[12], 6) + c
        a = rl(a, 10)
        c = rl(c + f1(d, e, a) + x[13], 7) + b
        e = rl(e, 10)
        b = rl(b + f1(c, d, e) + x[14], 9) + a
        d = rl(d, 10)
        a = rl(a + f1(b, c, d) + x[15], 8) + e
        c = rl(c, 10)

        // right
        aa = rl(aa + f5(bb, cc, dd) + x[5] + 0x50a28be6, 8) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f5(aa, bb, cc) + x[14] + 0x50a28be6, 9) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f5(ee, aa, bb) + x[7] + 0x50a28be6, 9) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f5(dd, ee, aa) + x[0] + 0x50a28be6, 11) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f5(cc, dd, ee) + x[9] + 0x50a28be6, 13) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f5(bb, cc, dd) + x[2] + 0x50a28be6, 15) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f5(aa, bb, cc) + x[11] + 0x50a28be6, 15) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f5(ee, aa, bb) + x[4] + 0x50a28be6, 5) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f5(dd, ee, aa) + x[13] + 0x50a28be6, 7) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f5(cc, dd, ee) + x[6] + 0x50a28be6, 7) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f5(bb, cc, dd) + x[15] + 0x50a28be6, 8) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f5(aa, bb, cc) + x[8] + 0x50a28be6, 11) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f5(ee, aa, bb) + x[1] + 0x50a28be6, 14) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f5(dd, ee, aa) + x[10] + 0x50a28be6, 14) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f5(cc, dd, ee) + x[3] + 0x50a28be6, 12) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f5(bb, cc, dd) + x[12] + 0x50a28be6, 6) + ee
        cc = rl(cc, 10)

        //
        // Rounds 16-31
        //
        // left
        e = rl(e + f2(a, b, c) + x[7] + 0x5a827999, 7) + d
        b = rl(b, 10)
        d = rl(d + f2(e, a, b) + x[4] + 0x5a827999, 6) + c
        a = rl(a, 10)
        c = rl(c + f2(d, e, a) + x[13] + 0x5a827999, 8) + b
        e = rl(e, 10)
        b = rl(b + f2(c, d, e) + x[1] + 0x5a827999, 13) + a
        d = rl(d, 10)
        a = rl(a + f2(b, c, d) + x[10] + 0x5a827999, 11) + e
        c = rl(c, 10)
        e = rl(e + f2(a, b, c) + x[6] + 0x5a827999, 9) + d
        b = rl(b, 10)
        d = rl(d + f2(e, a, b) + x[15] + 0x5a827999, 7) + c
        a = rl(a, 10)
        c = rl(c + f2(d, e, a) + x[3] + 0x5a827999, 15) + b
        e = rl(e, 10)
        b = rl(b + f2(c, d, e) + x[12] + 0x5a827999, 7) + a
        d = rl(d, 10)
        a = rl(a + f2(b, c, d) + x[0] + 0x5a827999, 12) + e
        c = rl(c, 10)
        e = rl(e + f2(a, b, c) + x[9] + 0x5a827999, 15) + d
        b = rl(b, 10)
        d = rl(d + f2(e, a, b) + x[5] + 0x5a827999, 9) + c
        a = rl(a, 10)
        c = rl(c + f2(d, e, a) + x[2] + 0x5a827999, 11) + b
        e = rl(e, 10)
        b = rl(b + f2(c, d, e) + x[14] + 0x5a827999, 7) + a
        d = rl(d, 10)
        a = rl(a + f2(b, c, d) + x[11] + 0x5a827999, 13) + e
        c = rl(c, 10)
        e = rl(e + f2(a, b, c) + x[8] + 0x5a827999, 12) + d
        b = rl(b, 10)

        // right
        ee = rl(ee + f4(aa, bb, cc) + x[6] + 0x5c4dd124, 9) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f4(ee, aa, bb) + x[11] + 0x5c4dd124, 13) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f4(dd, ee, aa) + x[3] + 0x5c4dd124, 15) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f4(cc, dd, ee) + x[7] + 0x5c4dd124, 7) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f4(bb, cc, dd) + x[0] + 0x5c4dd124, 12) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f4(aa, bb, cc) + x[13] + 0x5c4dd124, 8) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f4(ee, aa, bb) + x[5] + 0x5c4dd124, 9) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f4(dd, ee, aa) + x[10] + 0x5c4dd124, 11) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f4(cc, dd, ee) + x[14] + 0x5c4dd124, 7) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f4(bb, cc, dd) + x[15] + 0x5c4dd124, 7) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f4(aa, bb, cc) + x[8] + 0x5c4dd124, 12) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f4(ee, aa, bb) + x[12] + 0x5c4dd124, 7) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f4(dd, ee, aa) + x[4] + 0x5c4dd124, 6) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f4(cc, dd, ee) + x[9] + 0x5c4dd124, 15) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f4(bb, cc, dd) + x[1] + 0x5c4dd124, 13) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f4(aa, bb, cc) + x[2] + 0x5c4dd124, 11) + dd
        bb = rl(bb, 10)

        //
        // Rounds 32-47
        //
        // left
        d = rl(d + f3(e, a, b) + x[3] + 0x6ed9eba1, 11) + c
        a = rl(a, 10)
        c = rl(c + f3(d, e, a) + x[10] + 0x6ed9eba1, 13) + b
        e = rl(e, 10)
        b = rl(b + f3(c, d, e) + x[14] + 0x6ed9eba1, 6) + a
        d = rl(d, 10)
        a = rl(a + f3(b, c, d) + x[4] + 0x6ed9eba1, 7) + e
        c = rl(c, 10)
        e = rl(e + f3(a, b, c) + x[9] + 0x6ed9eba1, 14) + d
        b = rl(b, 10)
        d = rl(d + f3(e, a, b) + x[15] + 0x6ed9eba1, 9) + c
        a = rl(a, 10)
        c = rl(c + f3(d, e, a) + x[8] + 0x6ed9eba1, 13) + b
        e = rl(e, 10)
        b = rl(b + f3(c, d, e) + x[1] + 0x6ed9eba1, 15) + a
        d = rl(d, 10)
        a = rl(a + f3(b, c, d) + x[2] + 0x6ed9eba1, 14) + e
        c = rl(c, 10)
        e = rl(e + f3(a, b, c) + x[7] + 0x6ed9eba1, 8) + d
        b = rl(b, 10)
        d = rl(d + f3(e, a, b) + x[0] + 0x6ed9eba1, 13) + c
        a = rl(a, 10)
        c = rl(c + f3(d, e, a) + x[6] + 0x6ed9eba1, 6) + b
        e = rl(e, 10)
        b = rl(b + f3(c, d, e) + x[13] + 0x6ed9eba1, 5) + a
        d = rl(d, 10)
        a = rl(a + f3(b, c, d) + x[11] + 0x6ed9eba1, 12) + e
        c = rl(c, 10)
        e = rl(e + f3(a, b, c) + x[5] + 0x6ed9eba1, 7) + d
        b = rl(b, 10)
        d = rl(d + f3(e, a, b) + x[12] + 0x6ed9eba1, 5) + c
        a = rl(a, 10)

        // right
        dd = rl(dd + f3(ee, aa, bb) + x[15] + 0x6d703ef3, 9) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f3(dd, ee, aa) + x[5] + 0x6d703ef3, 7) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f3(cc, dd, ee) + x[1] + 0x6d703ef3, 15) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f3(bb, cc, dd) + x[3] + 0x6d703ef3, 11) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f3(aa, bb, cc) + x[7] + 0x6d703ef3, 8) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f3(ee, aa, bb) + x[14] + 0x6d703ef3, 6) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f3(dd, ee, aa) + x[6] + 0x6d703ef3, 6) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f3(cc, dd, ee) + x[9] + 0x6d703ef3, 14) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f3(bb, cc, dd) + x[11] + 0x6d703ef3, 12) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f3(aa, bb, cc) + x[8] + 0x6d703ef3, 13) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f3(ee, aa, bb) + x[12] + 0x6d703ef3, 5) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f3(dd, ee, aa) + x[2] + 0x6d703ef3, 14) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f3(cc, dd, ee) + x[10] + 0x6d703ef3, 13) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f3(bb, cc, dd) + x[0] + 0x6d703ef3, 13) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f3(aa, bb, cc) + x[4] + 0x6d703ef3, 7) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f3(ee, aa, bb) + x[13] + 0x6d703ef3, 5) + cc
        aa = rl(aa, 10)

        //
        // Rounds 48-63
        //
        // left
        c = rl(c + f4(d, e, a) + x[1] + -0x70e44324, 11) + b
        e = rl(e, 10)
        b = rl(b + f4(c, d, e) + x[9] + -0x70e44324, 12) + a
        d = rl(d, 10)
        a = rl(a + f4(b, c, d) + x[11] + -0x70e44324, 14) + e
        c = rl(c, 10)
        e = rl(e + f4(a, b, c) + x[10] + -0x70e44324, 15) + d
        b = rl(b, 10)
        d = rl(d + f4(e, a, b) + x[0] + -0x70e44324, 14) + c
        a = rl(a, 10)
        c = rl(c + f4(d, e, a) + x[8] + -0x70e44324, 15) + b
        e = rl(e, 10)
        b = rl(b + f4(c, d, e) + x[12] + -0x70e44324, 9) + a
        d = rl(d, 10)
        a = rl(a + f4(b, c, d) + x[4] + -0x70e44324, 8) + e
        c = rl(c, 10)
        e = rl(e + f4(a, b, c) + x[13] + -0x70e44324, 9) + d
        b = rl(b, 10)
        d = rl(d + f4(e, a, b) + x[3] + -0x70e44324, 14) + c
        a = rl(a, 10)
        c = rl(c + f4(d, e, a) + x[7] + -0x70e44324, 5) + b
        e = rl(e, 10)
        b = rl(b + f4(c, d, e) + x[15] + -0x70e44324, 6) + a
        d = rl(d, 10)
        a = rl(a + f4(b, c, d) + x[14] + -0x70e44324, 8) + e
        c = rl(c, 10)
        e = rl(e + f4(a, b, c) + x[5] + -0x70e44324, 6) + d
        b = rl(b, 10)
        d = rl(d + f4(e, a, b) + x[6] + -0x70e44324, 5) + c
        a = rl(a, 10)
        c = rl(c + f4(d, e, a) + x[2] + -0x70e44324, 12) + b
        e = rl(e, 10)

        // right
        cc = rl(cc + f2(dd, ee, aa) + x[8] + 0x7a6d76e9, 15) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f2(cc, dd, ee) + x[6] + 0x7a6d76e9, 5) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f2(bb, cc, dd) + x[4] + 0x7a6d76e9, 8) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f2(aa, bb, cc) + x[1] + 0x7a6d76e9, 11) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f2(ee, aa, bb) + x[3] + 0x7a6d76e9, 14) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f2(dd, ee, aa) + x[11] + 0x7a6d76e9, 14) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f2(cc, dd, ee) + x[15] + 0x7a6d76e9, 6) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f2(bb, cc, dd) + x[0] + 0x7a6d76e9, 14) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f2(aa, bb, cc) + x[5] + 0x7a6d76e9, 6) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f2(ee, aa, bb) + x[12] + 0x7a6d76e9, 9) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f2(dd, ee, aa) + x[2] + 0x7a6d76e9, 12) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f2(cc, dd, ee) + x[13] + 0x7a6d76e9, 9) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f2(bb, cc, dd) + x[9] + 0x7a6d76e9, 12) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f2(aa, bb, cc) + x[7] + 0x7a6d76e9, 5) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f2(ee, aa, bb) + x[10] + 0x7a6d76e9, 15) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f2(dd, ee, aa) + x[14] + 0x7a6d76e9, 8) + bb
        ee = rl(ee, 10)

        //
        // Rounds 64-79
        //
        // left
        b = rl(b + f5(c, d, e) + x[4] + -0x56ac02b2, 9) + a
        d = rl(d, 10)
        a = rl(a + f5(b, c, d) + x[0] + -0x56ac02b2, 15) + e
        c = rl(c, 10)
        e = rl(e + f5(a, b, c) + x[5] + -0x56ac02b2, 5) + d
        b = rl(b, 10)
        d = rl(d + f5(e, a, b) + x[9] + -0x56ac02b2, 11) + c
        a = rl(a, 10)
        c = rl(c + f5(d, e, a) + x[7] + -0x56ac02b2, 6) + b
        e = rl(e, 10)
        b = rl(b + f5(c, d, e) + x[12] + -0x56ac02b2, 8) + a
        d = rl(d, 10)
        a = rl(a + f5(b, c, d) + x[2] + -0x56ac02b2, 13) + e
        c = rl(c, 10)
        e = rl(e + f5(a, b, c) + x[10] + -0x56ac02b2, 12) + d
        b = rl(b, 10)
        d = rl(d + f5(e, a, b) + x[14] + -0x56ac02b2, 5) + c
        a = rl(a, 10)
        c = rl(c + f5(d, e, a) + x[1] + -0x56ac02b2, 12) + b
        e = rl(e, 10)
        b = rl(b + f5(c, d, e) + x[3] + -0x56ac02b2, 13) + a
        d = rl(d, 10)
        a = rl(a + f5(b, c, d) + x[8] + -0x56ac02b2, 14) + e
        c = rl(c, 10)
        e = rl(e + f5(a, b, c) + x[11] + -0x56ac02b2, 11) + d
        b = rl(b, 10)
        d = rl(d + f5(e, a, b) + x[6] + -0x56ac02b2, 8) + c
        a = rl(a, 10)
        c = rl(c + f5(d, e, a) + x[15] + -0x56ac02b2, 5) + b
        e = rl(e, 10)
        b = rl(b + f5(c, d, e) + x[13] + -0x56ac02b2, 6) + a
        d = rl(d, 10)

        // right
        bb = rl(bb + f1(cc, dd, ee) + x[12], 8) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f1(bb, cc, dd) + x[15], 5) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f1(aa, bb, cc) + x[10], 12) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f1(ee, aa, bb) + x[4], 9) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f1(dd, ee, aa) + x[1], 12) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f1(cc, dd, ee) + x[5], 5) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f1(bb, cc, dd) + x[8], 14) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f1(aa, bb, cc) + x[7], 6) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f1(ee, aa, bb) + x[6], 8) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f1(dd, ee, aa) + x[2], 13) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f1(cc, dd, ee) + x[13], 6) + aa
        dd = rl(dd, 10)
        aa = rl(aa + f1(bb, cc, dd) + x[14], 5) + ee
        cc = rl(cc, 10)
        ee = rl(ee + f1(aa, bb, cc) + x[0], 15) + dd
        bb = rl(bb, 10)
        dd = rl(dd + f1(ee, aa, bb) + x[3], 13) + cc
        aa = rl(aa, 10)
        cc = rl(cc + f1(dd, ee, aa) + x[9], 11) + bb
        ee = rl(ee, 10)
        bb = rl(bb + f1(cc, dd, ee) + x[11], 11) + aa
        dd = rl(dd, 10)
        dd += c + h1
        h1 = h2 + d + ee
        h2 = h3 + e + aa
        h3 = h4 + a + bb
        h4 = h0 + b + cc
        h0 = dd

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0
        for (i in x.indices) {
            x[i] = 0
        }
    }

    override fun copy(): Memoable {
        return RIPEMD160Digest(this)
    }

    override fun reset(other: Memoable) {
        copyIn(other as RIPEMD160Digest)
    }
}
