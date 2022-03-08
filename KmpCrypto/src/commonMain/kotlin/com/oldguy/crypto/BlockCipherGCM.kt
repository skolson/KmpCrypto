package com.oldguy.crypto

/**
 * helper functions for Big Endian support not yet available with ByteArray, UByteArray
 */
object Pack {
    fun bigEndianToInt(bs: UByteArray, offset: Int): Int {
        var off = offset
        var n = (bs[off] and 0xffu).toInt() shl 24
        n = n or (bs[++off] and 0xffu).toInt() shl 16
        n = n or (bs[++off] and 0xffu).toInt() shl 8
        n = n or (bs[++off] and 0xffu).toInt()
        return n
    }

    fun bigEndianToInt(bs: UByteArray, offset: Int, ns: IntArray) {
        var off = offset
        for (i in ns.indices) {
            ns[i] = bigEndianToInt(bs, off)
            off += 4
        }
    }

    fun intToBigEndian(n: Int, bs: UByteArray, offset: Int = 0) {
        var off = offset
        bs[off] = (n ushr 24).toUByte()
        bs[++off] = (n ushr 16).toUByte()
        bs[++off] = (n ushr 8).toUByte()
        bs[++off] = n.toUByte()
    }

    fun intToBigEndian(ns: IntArray, bs: UByteArray, offset: Int = 0) {
        var off = offset
        for (i in ns.indices) {
            intToBigEndian(ns[i], bs, off)
            off += 4
        }
    }

    fun bigEndianToLong(bs: UByteArray, off: Int): Long {
        val hi = bigEndianToInt(bs, off)
        val lo = bigEndianToInt(bs, off + 4)
        return ((hi.toLong() and 0xffffffffL) shl 32) or
                (lo.toLong() and 0xffffffffL)
    }

    fun bigEndianToLong(bs: UByteArray, offset: Int, ns: LongArray) {
        var off = offset
        for (i in ns.indices) {
            ns[i] = bigEndianToLong(bs, off)
            off += 8
        }
    }

    fun longToBigEndian(n: Long, bs: UByteArray, off: Int) {
        intToBigEndian((n ushr 32).toInt(), bs, off)
        intToBigEndian((n and 0xffffffffL).toInt(), bs, off + 4)
    }

    fun longToBigEndian(ns: LongArray, bs: UByteArray, offset: Int = 0) {
        var off = offset
        for (i in ns.indices) {
            longToBigEndian(ns[i], bs, off)
            off += 8
        }
    }
}

object Interleave {
    private const val M32 = 0x55555555L
    private const val M64 = 0x5555555555555555L
    private const val M64R = -0x5555555555555556L

    /*
     * This expands 8 bit indices into 16 bit contents (high bit 14), by inserting 0s between bits.
     * In a binary field, this operation is the same as squaring an 8 bit number.
     *
     * NOTE: All entries are positive so sign-extension is not an issue.
     */
    fun expand8to16(xIn: Int): Int {
        var x = xIn
        x = x and 0xFF
        x = x or (x shl 4) and 0x0F0F
        x = x or (x shl 2) and 0x3333
        x = x or (x shl 1) and 0x5555
        return x
    }

    fun expand16to32(xIn: Int): Int {
        var x = xIn
        x = x and 0xFFFF
        x = x or (x shl 8) and 0x00FF00FF
        x = x or (x shl 4) and 0x0F0F0F0F
        x = x or (x shl 2) and 0x33333333
        x = x or (x shl 1) and 0x55555555
        return x
    }

    fun expand32to64(xIn: Int): Long {
        // "shuffle" low half to even bits and high half to odd bits
        var x = xIn
        var t: Int
        t = x xor (x ushr 8) and 0x0000FF00
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 4) and 0x00F000F0
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 2) and 0x0C0C0C0C
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 1) and 0x22222222
        x = x xor (t xor (t shl 1))
        return (x ushr 1 and M32.toInt() shl 32 or (x and M32.toInt())).toLong()
    }

    fun expand64To128(xIn: Long, z: LongArray, zOff: Int) {
        // "shuffle" low half to even bits and high half to odd bits
        var x = xIn
        var t: Long
        t = x xor (x ushr 16) and 0x00000000FFFF0000L
        x = x xor (t xor (t shl 16))
        t = x xor (x ushr 8) and 0x0000FF000000FF00L
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 4) and 0x00F000F000F000F0L
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 2) and 0x0C0C0C0C0C0C0C0CL
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 1) and 0x2222222222222222L
        x = x xor (t xor (t shl 1))
        z[zOff] = x and M64
        z[zOff + 1] = x ushr 1 and M64
    }

    fun expand64To128Rev(xIn: Long, z: LongArray, zOff: Int) {
        // "shuffle" low half to even bits and high half to odd bits
        var x = xIn
        var t: Long
        t = x xor (x ushr 16) and 0x00000000FFFF0000L
        x = x xor (t xor (t shl 16))
        t = x xor (x ushr 8) and 0x0000FF000000FF00L
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 4) and 0x00F000F000F000F0L
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 2) and 0x0C0C0C0C0C0C0C0CL
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 1) and 0x2222222222222222L
        x = x xor (t xor (t shl 1))
        z[zOff] = x and M64R
        z[zOff + 1] = x shl 1 and M64R
    }

    fun shuffle(xIn: Int): Int {
        // "shuffle" low half to even bits and high half to odd bits
        var x = xIn
        var t: Int
        t = x xor (x ushr 8) and 0x0000FF00
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 4) and 0x00F000F0
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 2) and 0x0C0C0C0C
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 1) and 0x22222222
        x = x xor (t xor (t shl 1))
        return x
    }

    fun shuffle(xIn: Long): Long {
        // "shuffle" low half to even bits and high half to odd bits
        var x = xIn
        var t: Long
        t = x xor (x ushr 16) and 0x00000000FFFF0000L
        x = x xor (t xor (t shl 16))
        t = x xor (x ushr 8) and 0x0000FF000000FF00L
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 4) and 0x00F000F000F000F0L
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 2) and 0x0C0C0C0C0C0C0C0CL
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 1) and 0x2222222222222222L
        x = x xor (t xor (t shl 1))
        return x
    }

    fun shuffle2(xIn: Int): Int {
        // "shuffle" (twice) low half to even bits and high half to odd bits
        var x = xIn
        var t: Int
        t = x xor (x ushr 7) and 0x00AA00AA
        x = x xor (t xor (t shl 7))
        t = x xor (x ushr 14) and 0x0000CCCC
        x = x xor (t xor (t shl 14))
        t = x xor (x ushr 4) and 0x00F000F0
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 8) and 0x0000FF00
        x = x xor (t xor (t shl 8))
        return x
    }

    fun unshuffle(xIn: Int): Int {
        // "unshuffle" even bits to low half and odd bits to high half
        var x = xIn
        var t: Int
        t = x xor (x ushr 1) and 0x22222222
        x = x xor (t xor (t shl 1))
        t = x xor (x ushr 2) and 0x0C0C0C0C
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 4) and 0x00F000F0
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 8) and 0x0000FF00
        x = x xor (t xor (t shl 8))
        return x
    }

    fun unshuffle(xIn: Long): Long {
        // "unshuffle" even bits to low half and odd bits to high half
        var x = xIn
        var t: Long
        t = x xor (x ushr 1) and 0x2222222222222222L
        x = x xor (t xor (t shl 1))
        t = x xor (x ushr 2) and 0x0C0C0C0C0C0C0C0CL
        x = x xor (t xor (t shl 2))
        t = x xor (x ushr 4) and 0x00F000F000F000F0L
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 8) and 0x0000FF000000FF00L
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 16) and 0x00000000FFFF0000L
        x = x xor (t xor (t shl 16))
        return x
    }

    fun unshuffle2(xIn: Int): Int {
        // "unshuffle" (twice) even bits to low half and odd bits to high half
        var x = xIn
        var t: Int
        t = x xor (x ushr 8) and 0x0000FF00
        x = x xor (t xor (t shl 8))
        t = x xor (x ushr 4) and 0x00F000F0
        x = x xor (t xor (t shl 4))
        t = x xor (x ushr 14) and 0x0000CCCC
        x = x xor (t xor (t shl 14))
        t = x xor (x ushr 7) and 0x00AA00AA
        x = x xor (t xor (t shl 7))
        return x
    }
}

interface GCMExponentiator {
    fun init(x: UByteArray)
    fun exponentiateX(pow: Long, output: UByteArray)
}

object GCMUtil {
    private const val E1 = -0x1f000000
    private const val E1L = ((E1.toLong() and 0xFFFFFFFFL) shl 32)

    fun oneAsBytes(): ByteArray {
        val tmp = ByteArray(16)
        tmp[0] = 0x80.toByte()
        return tmp
    }

    fun oneAsInts(): IntArray {
        val tmp = IntArray(4)
        tmp[0] = 1 shl 31
        return tmp
    }

    fun oneAsLongs(): LongArray {
        val tmp = LongArray(2)
        tmp[0] = 1L shl 63
        return tmp
    }

    fun asBytes(x: IntArray): UByteArray {
        val z = UByteArray(16)
        Pack.intToBigEndian(x, z, 0)
        return z
    }

    fun asBytes(x: IntArray, z: UByteArray) {
        Pack.intToBigEndian(x, z, 0)
    }

    fun asBytes(x: LongArray): UByteArray {
        val z = UByteArray(16)
        Pack.longToBigEndian(x, z, 0)
        return z
    }

    fun asBytes(x: LongArray, z: UByteArray) {
        Pack.longToBigEndian(x, z, 0)
    }

    fun asInts(x: UByteArray): IntArray {
        val z = IntArray(4)
        Pack.bigEndianToInt(x, 0, z)
        return z
    }

    fun asInts(x: UByteArray, z: IntArray) {
        Pack.bigEndianToInt(x, 0, z)
    }

    fun asLongs(x: UByteArray): LongArray {
        val z = LongArray(2)
        Pack.bigEndianToLong(x, 0, z)
        return z
    }

    fun asLongs(x: UByteArray, z: LongArray) {
        Pack.bigEndianToLong(x, 0, z)
    }

    fun copy(x: IntArray, z: IntArray) {
        z[0] = x[0]
        z[1] = x[1]
        z[2] = x[2]
        z[3] = x[3]
    }

    fun copy(x: LongArray, z: LongArray) {
        z[0] = x[0]
        z[1] = x[1]
    }

    fun divideP(x: LongArray, z: LongArray) {
        var x0 = x[0]
        val x1 = x[1]
        val m = x0 shr 63
        x0 = x0 xor (m and E1L)
        z[0] = x0 shl 1 or (x1 ushr 63)
        z[1] = x1 shl 1 or -m
    }

    fun multiply(x: UByteArray, y: UByteArray) {
        val t1 = asLongs(x)
        val t2 = asLongs(y)
        multiply(t1, t2)
        asBytes(t1, x)
    }

    fun multiply(x: IntArray, y: IntArray) {
        var y0 = y[0]
        var y1 = y[1]
        var y2 = y[2]
        var y3 = y[3]
        var z0 = 0
        var z1 = 0
        var z2 = 0
        var z3 = 0
        for (i in 0..3) {
            var bits = x[i]
            for (j in 0..31) {
                val m1 = bits shr 31
                bits = bits shl 1
                z0 = z0 xor (y0 and m1)
                z1 = z1 xor (y1 and m1)
                z2 = z2 xor (y2 and m1)
                z3 = z3 xor (y3 and m1)
                val m2 = y3 shl 31 shr 8
                y3 = (y3 ushr 1) or (y2 shl 31)
                y2 = (y2 ushr 1) or (y1 shl 31)
                y1 = (y1 ushr 1) or (y0 shl 31)
                y0 = (y0 ushr 1) xor (m2 and E1)
            }
        }
        x[0] = z0
        x[1] = z1
        x[2] = z2
        x[3] = z3
    }

    fun multiply(x: LongArray, y: LongArray) {
        var x0 = x[0]
        var x1 = x[1]
        var y0 = y[0]
        var y1 = y[1]
        var z0: Long = 0
        var z1: Long = 0
        var z2: Long = 0
        for (j in 0..63) {
            val m0 = x0 shr 63
            x0 = x0 shl 1
            z0 = z0 xor (y0 and m0)
            z1 = z1 xor (y1 and m0)
            val m1 = x1 shr 63
            x1 = x1 shl 1
            z1 = z1 xor (y0 and m1)
            z2 = z2 xor (y1 and m1)
            val c = y1 shl 63 shr 8
            y1 = (y1 ushr 1) or (y0 shl 63)
            y0 = (y0 ushr 1) xor (c and E1L)
        }
        z0 = z0 xor (z2 xor (z2 ushr 1) xor (z2 ushr 2) xor (z2 ushr 7))
        z1 = z1 xor (z2 shl 63 xor (z2 shl 62) xor (z2 shl 57))
        x[0] = z0
        x[1] = z1
    }

    fun multiplyP(x: IntArray) {
        val x0 = x[0]
        val x1 = x[1]
        val x2 = x[2]
        val x3 = x[3]
        val m = x3 shl 31 shr 31
        x[0] = x0 ushr 1 xor (m and E1)
        x[1] = x1 ushr 1 or (x0 shl 31)
        x[2] = x2 ushr 1 or (x1 shl 31)
        x[3] = x3 ushr 1 or (x2 shl 31)
    }

    fun multiplyP(x: IntArray, z: IntArray) {
        val x0 = x[0]
        val x1 = x[1]
        val x2 = x[2]
        val x3 = x[3]
        val m = x3 shl 31 shr 31
        z[0] = x0 ushr 1 xor (m and E1)
        z[1] = x1 ushr 1 or (x0 shl 31)
        z[2] = x2 ushr 1 or (x1 shl 31)
        z[3] = x3 ushr 1 or (x2 shl 31)
    }

    fun multiplyP(x: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val m = x1 shl 63 shr 63
        x[0] = x0 ushr 1 xor (m and E1L)
        x[1] = x1 ushr 1 or (x0 shl 63)
    }

    fun multiplyP(x: LongArray, z: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val m = x1 shl 63 shr 63
        z[0] = x0 ushr 1 xor (m and E1L)
        z[1] = x1 ushr 1 or (x0 shl 63)
    }

    fun multiplyP3(x: LongArray, z: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val c = x1 shl 61
        z[0] = x0 ushr 3 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        z[1] = x1 ushr 3 or (x0 shl 61)
    }

    fun multiplyP4(x: LongArray, z: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val c = x1 shl 60
        z[0] = x0 ushr 4 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        z[1] = x1 ushr 4 or (x0 shl 60)
    }

    fun multiplyP7(x: LongArray, z: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val c = x1 shl 57
        z[0] = x0 ushr 7 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        z[1] = x1 ushr 7 or (x0 shl 57)
    }

    fun multiplyP8(x: IntArray) {
        val x0 = x[0]
        val x1 = x[1]
        val x2 = x[2]
        val x3 = x[3]
        val c = x3 shl 24
        x[0] = x0 ushr 8 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        x[1] = x1 ushr 8 or (x0 shl 24)
        x[2] = x2 ushr 8 or (x1 shl 24)
        x[3] = x3 ushr 8 or (x2 shl 24)
    }

    fun multiplyP8(x: IntArray, y: IntArray) {
        val x0 = x[0]
        val x1 = x[1]
        val x2 = x[2]
        val x3 = x[3]
        val c = x3 shl 24
        y[0] = x0 ushr 8 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        y[1] = x1 ushr 8 or (x0 shl 24)
        y[2] = x2 ushr 8 or (x1 shl 24)
        y[3] = x3 ushr 8 or (x2 shl 24)
    }

    fun multiplyP8(x: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val c = x1 shl 56
        x[0] = x0 ushr 8 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        x[1] = x1 ushr 8 or (x0 shl 56)
    }

    fun multiplyP8(x: LongArray, y: LongArray) {
        val x0 = x[0]
        val x1 = x[1]
        val c = x1 shl 56
        y[0] = x0 ushr 8 xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        y[1] = x1 ushr 8 or (x0 shl 56)
    }

    fun pAsLongs(): LongArray {
        val tmp = LongArray(2)
        tmp[0] = 1L shl 62
        return tmp
    }

    fun square(x: LongArray, z: LongArray) {
        val t = LongArray(4)
        Interleave.expand64To128Rev(x[0], t, 0)
        Interleave.expand64To128Rev(x[1], t, 2)
        var z0 = t[0]
        var z1 = t[1]
        var z2 = t[2]
        val z3 = t[3]
        z1 = z1 xor (z3 xor (z3 ushr 1) xor (z3 ushr 2) xor (z3 ushr 7))
        z2 = z2 xor (z3 shl 63 xor (z3 shl 62) xor (z3 shl 57))
        z0 = z0 xor (z2 xor (z2 ushr 1) xor (z2 ushr 2) xor (z2 ushr 7))
        z1 = z1 xor (z2 shl 63 xor (z2 shl 62) xor (z2 shl 57))
        z[0] = z0
        z[1] = z1
    }

    fun xor(x: UByteArray, y: UByteArray) {
        var i = 0
        do {
            x[i] = x[i] xor y[i]
            ++i
            x[i] = x[i] xor y[i]
            ++i
            x[i] = x[i] xor y[i]
            ++i
            x[i] = x[i] xor y[i]
            ++i
        } while (i < 16)
    }

    fun xor(x: UByteArray, y: UByteArray, yOff: Int) {
        var i = 0
        do {
            x[i] = x[i] xor y[yOff + i]
            ++i
            x[i] = x[i] xor y[yOff + i]
            ++i
            x[i] = x[i] xor y[yOff + i]
            ++i
            x[i] = x[i] xor y[yOff + i]
            ++i
        } while (i < 16)
    }

    fun xor(x: UByteArray, xOff: Int, y: UByteArray, yOff: Int, z: UByteArray, zOff: Int) {
        var i = 0
        do {
            z[zOff + i] = (x[xOff + i] xor y[yOff + i])
            ++i
            z[zOff + i] = (x[xOff + i] xor y[yOff + i])
            ++i
            z[zOff + i] = (x[xOff + i] xor y[yOff + i])
            ++i
            z[zOff + i] = (x[xOff + i] xor y[yOff + i])
            ++i
        } while (i < 16)
    }

    fun xor(x: UByteArray, y: UByteArray, yOff: Int, yLength: Int) {
        var yLen = yLength
        while (--yLen >= 0) {
            x[yLen] = x[yLen] xor y[yOff + yLen]
        }
    }

    fun xor(x: UByteArray, xOff: Int, y: UByteArray, yOff: Int, length: Int) {
        var len = length
        while (--len >= 0) {
            x[xOff + len] = x[xOff + len] xor y[yOff + len]
        }
    }

    fun xor(x: UByteArray, y: UByteArray, z: UByteArray) {
        var i = 0
        do {
            z[i] = (x[i] xor y[i])
            ++i
            z[i] = (x[i] xor y[i])
            ++i
            z[i] = (x[i] xor y[i])
            ++i
            z[i] = (x[i] xor y[i])
            ++i
        } while (i < 16)
    }

    fun xor(x: IntArray, y: IntArray) {
        x[0] = x[0] xor y[0]
        x[1] = x[1] xor y[1]
        x[2] = x[2] xor y[2]
        x[3] = x[3] xor y[3]
    }

    fun xor(x: IntArray, y: IntArray, z: IntArray) {
        z[0] = x[0] xor y[0]
        z[1] = x[1] xor y[1]
        z[2] = x[2] xor y[2]
        z[3] = x[3] xor y[3]
    }

    fun xor(x: LongArray, y: LongArray) {
        x[0] = x[0] xor y[0]
        x[1] = x[1] xor y[1]
    }

    fun xor(x: LongArray, y: LongArray, z: LongArray) {
        z[0] = x[0] xor y[0]
        z[1] = x[1] xor y[1]
    }
}

interface GCMMultiplier {
    fun init(h: UByteArray)
    fun multiplyH(x: UByteArray)
}

class BasicGCMExponentiator : GCMExponentiator {
    private var x = LongArray(0)

    override fun init(x: UByteArray) {
        this.x = GCMUtil.asLongs(x)
    }

    override fun exponentiateX(pow: Long, output: UByteArray) {
        // Initial value is little-endian 1
        var p = pow
        val y: LongArray = GCMUtil.oneAsLongs()
        if (p > 0) {
            val powX = x.copyOf()
            do {
                if (p and 1L != 0L) {
                    GCMUtil.multiply(y, powX)
                }
                GCMUtil.square(powX, powX)
                p = p ushr 1
            } while (p > 0)
        }
        GCMUtil.asBytes(y, output)
    }
}

class Tables4kGCMMultiplier : GCMMultiplier {
    private var H = UByteArray(0)
    private var T = Array(256) { LongArray(2) }

    override fun init(h: UByteArray) {
        if (H contentEquals h) return
        H = h.copyOf()

        // T[0] = 0

        // T[1] = H.p^7
        GCMUtil.asLongs(this.H, T[1])
        GCMUtil.multiplyP7(T[1], T[1])
        var n = 2
        while (n < 256) {

            // T[2.n] = T[n].p^-1
            GCMUtil.divideP(T[n shr 1], T[n])

            // T[2.n + 1] = T[2.n] + T[1]
            GCMUtil.xor(T[n], T[1], T[n + 1])
            n += 2
        }
    }

    override fun multiplyH(x: UByteArray) {
//        long[] z = new long[2];
//        GCMUtil.copy(T[x[15] & 0xFF], z);
//        for (int i = 14; i >= 0; --i)
//        {
//            GCMUtil.multiplyP8(z);
//            GCMUtil.xor(z, T[x[i] & 0xFF]);
//        }
//        Pack.longToBigEndian(z, x, 0);
        var t = T[(x[15] and 0xFFu).toInt()]
        var z0 = t[0]
        var z1 = t[1]
        for (i in 14 downTo 0) {
            t = T[(x[i] and 0xFFu).toInt()]
            val c = z1 shl 56
            z1 = t[1] xor (z1 ushr 8 or (z0 shl 56))
            z0 = t[0] xor (z0 ushr 8) xor c xor (c ushr 1) xor (c ushr 2) xor (c ushr 7)
        }
        Pack.longToBigEndian(z0, x, 0)
        Pack.longToBigEndian(z1, x, 8)
    }
}

/**
 * Implements the Galois/Counter mode (GCM) detailed in
 * NIST Special Publication 800-38D.
 */
class GCMBlockCipher(c: BlockCipher, m: GCMMultiplier = Tables4kGCMMultiplier()) : AEADBlockCipher {

    override val cipher = c
    override val algorithmName = "${cipher.algorithmName}/GCM"
    override val blockSize = c.blockSize
    override val ivSize = 12

    private val multiplier = m
    private lateinit var exp: GCMExponentiator

    // These fields are set by init and not modified by processing
    private var forEncryption = false
    private var initialised = false
    private var macSize = 0
    private var lastKey = UByteArray(0)
    private var nonce = UByteArray(0)
    private var initialAssociatedText = UByteArray(0)
    private var H = UByteArray(0)
    private var J0 = UByteArray(0)

    // These fields are modified during processing
    private var bufBlock = UByteArray(0)
    override var mac = UByteArray(0)
    private var macBlock = UByteArray(0)
        set(value) {
            field = value
            mac = if (macBlock.isEmpty())
                UByteArray(macSize)
            else
                macBlock.copyOf()
        }
    private var S = UByteArray(0)
    private var S_at = UByteArray(0)
    private var S_atPre = UByteArray(0)
    private var counter = UByteArray(0)
    private var blocksRemaining = 0
    private var bufOff = 0
    private var totalLength: Long = 0
    private var atBlock = UByteArray(0)
    private var atBlockPos = 0
    private var atLength: Long = 0
    private var atLengthPre: Long = 0

    init {
        if (c.blockSize != BLOCK_SIZE) {
            throw IllegalArgumentException("cipher required with a block size of $BLOCK_SIZE.")
        }
    }

    /**
     * NOTE: MAC sizes from 32 bits to 128 bits (must be a multiple of 8) are supported. The default is 128 bits.
     * Sizes less than 96 are not recommended, but are supported for specialized applications.
     */
    override fun init(forEncryption: Boolean, params: CipherParameters) {
        this.forEncryption = forEncryption
        macBlock = UByteArray(0)
        initialised = true
        val keyParam: KeyParameter
        val newNonce = if (params is AEADParameters) {
            val param = params
            initialAssociatedText = param.associatedText
            val macSizeBits: Int = param.macSize
            if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0) {
                throw IllegalArgumentException("Invalid value for MAC size: $macSizeBits")
            }
            macSize = macSizeBits / 8
            keyParam = param.key
            param.nonce
        } else if (params is ParametersWithIV) {
            initialAssociatedText = UByteArray(0)
            macSize = 16
            keyParam = params.parameters as KeyParameter
            params.iV
        } else {
            throw IllegalArgumentException("invalid parameters passed to GCM")
        }
        val bufLength = if (forEncryption) BLOCK_SIZE else BLOCK_SIZE + macSize
        bufBlock = UByteArray(bufLength)
        if (newNonce.isEmpty()) {
            throw IllegalArgumentException("IV must be at least 1 byte")
        }
        if (forEncryption) {
            if (nonce.isNotEmpty() && (nonce contentEquals newNonce)) {
                if (lastKey.isNotEmpty() && (lastKey contentEquals keyParam.key)) {
                    throw IllegalArgumentException("cannot reuse nonce for GCM encryption")
                }
            }
        }
        nonce = newNonce
        lastKey = keyParam.key

        // Cipher always used in forward mode
        // if keyParam is null we're reusing the last key.
        cipher.init(true, keyParam)
        H = UByteArray(BLOCK_SIZE)
        cipher.processBlock(H, 0, H, 0)

        // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
        multiplier.init(H)

        J0 = UByteArray(BLOCK_SIZE)
        if (nonce.size == 12) {
            nonce.copyInto(J0)
            J0[BLOCK_SIZE - 1] = 1u
        } else {
            gHASH(J0, nonce, nonce.size)
            val X = UByteArray(BLOCK_SIZE)
            Pack.longToBigEndian(nonce.size.toLong() * 8, X, 8)
            gHASHBlock(J0, X)
        }
        S = UByteArray(BLOCK_SIZE)
        S_at = UByteArray(BLOCK_SIZE)
        S_atPre = UByteArray(BLOCK_SIZE)
        atBlock = UByteArray(BLOCK_SIZE)
        atBlockPos = 0
        atLength = 0
        atLengthPre = 0
        counter = J0.copyOf()
        blocksRemaining = -2 // page 8, len(P) <= 2^39 - 256, 1 block used by tag but done on J0
        bufOff = 0
        totalLength = 0
        if (initialAssociatedText.isNotEmpty()) {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.size)
        }
    }

    override fun getOutputSize(length: Int): Int {
        val totalData = length + bufOff
        if (forEncryption) {
            return totalData + macSize
        }
        return if (totalData < macSize) 0 else totalData - macSize
    }

    override fun getUpdateOutputSize(length: Int): Int {
        var totalData = length + bufOff
        if (!forEncryption) {
            if (totalData < macSize) {
                return 0
            }
            totalData -= macSize
        }
        return totalData - totalData % BLOCK_SIZE
    }

    override fun processAADByte(byte: UByte) {
        checkStatus()
        atBlock[atBlockPos] = byte
        if (++atBlockPos == BLOCK_SIZE) {
            // Hash each block as it fills
            gHASHBlock(S_at, atBlock)
            atBlockPos = 0
            atLength += BLOCK_SIZE.toLong()
        }
    }

    override fun processAADBytes(bytes: UByteArray, inOffset: Int, length: Int) {
        checkStatus()
        for (i in 0 until length) {
            atBlock[atBlockPos] = bytes[inOffset + i]
            if (++atBlockPos == BLOCK_SIZE) {
                // Hash each block as it fills
                gHASHBlock(S_at, atBlock)
                atBlockPos = 0
                atLength += BLOCK_SIZE.toLong()
            }
        }
    }

    private fun initCipher() {
        if (atLength > 0) {
            S_at.copyInto(S_atPre, 0, 0, BLOCK_SIZE)
            atLengthPre = atLength
        }

        // Finish hash for partial AAD block
        if (atBlockPos > 0) {
            gHASHPartial(S_atPre, atBlock, 0, atBlockPos)
            atLengthPre += atBlockPos.toLong()
        }
        if (atLengthPre > 0) {
            S_atPre.copyInto(S, 0, 0, BLOCK_SIZE)
        }
    }

    override fun processByte(byte: UByte, out: UByteArray, outOffset: Int): Int {
        checkStatus()
        bufBlock[bufOff] = byte
        if (++bufOff == bufBlock.size) {
            processBlock(bufBlock, 0, out, outOffset)
            bufOff = if (forEncryption) {
                0
            } else {
                bufBlock.copyInto(bufBlock, 0, BLOCK_SIZE, BLOCK_SIZE + macSize)
                macSize
            }
            return BLOCK_SIZE
        }
        return 0
    }

    override fun processBytes(
        bytes: UByteArray,
        inOffset: Int,
        length: Int,
        out: UByteArray,
        outOffset: Int
    ): Int {
        var inOff = inOffset
        var len = length
        checkStatus()
        if (bytes.size - inOff < len) {
            throw IllegalArgumentException("Input buffer too short")
        }
        var resultLen = 0
        if (forEncryption) {
            if (bufOff != 0) {
                while (len > 0) {
                    --len
                    bufBlock[bufOff] = bytes[inOff++]
                    if (++bufOff == BLOCK_SIZE) {
                        processBlock(bufBlock, 0, out, outOffset)
                        bufOff = 0
                        resultLen += BLOCK_SIZE
                        break
                    }
                }
            }
            while (len >= BLOCK_SIZE) {
                processBlock(bytes, inOff, out, outOffset + resultLen)
                inOff += BLOCK_SIZE
                len -= BLOCK_SIZE
                resultLen += BLOCK_SIZE
            }
            if (len > 0) {
                bytes.copyInto(bufBlock, 0, inOff, inOff + len)
                bufOff = len
            }
        } else {
            for (i in 0 until len) {
                bufBlock[bufOff] = bytes[inOff + i]
                if (++bufOff == bufBlock.size) {
                    processBlock(bufBlock, 0, out, outOffset + resultLen)
                    bufBlock.copyInto(bufBlock, 0, BLOCK_SIZE, BLOCK_SIZE + macSize)
                    bufOff = macSize
                    resultLen += BLOCK_SIZE
                }
            }
        }
        return resultLen
    }

    override fun doFinal(out: UByteArray, outOffset: Int): Int {
        checkStatus()
        if (totalLength == 0L) {
            initCipher()
        }
        var extra = bufOff
        if (forEncryption) {
            if (out.size - outOffset < extra + macSize) {
                throw IllegalArgumentException("Output buffer too short")
            }
        } else {
            if (extra < macSize) {
                throw IllegalArgumentException("data too short")
            }
            extra -= macSize
            if (out.size - outOffset < extra) {
                throw IllegalArgumentException("Output buffer too short")
            }
        }
        if (extra > 0) {
            processPartial(bufBlock, 0, extra, out, outOffset)
        }
        atLength += atBlockPos.toLong()
        if (atLength > atLengthPre) {
            /*
             *  Some AAD was sent after the cipher started. We determine the difference b/w the hash value
             *  we actually used when the cipher started (S_atPre) and the final hash value calculated (S_at).
             *  Then we carry this difference forward by multiplying by H^c, where c is the number of (full or
             *  partial) cipher-text blocks produced, and adjust the current hash.
             */

            // Finish hash for partial AAD block
            if (atBlockPos > 0) {
                gHASHPartial(S_at, atBlock, 0, atBlockPos)
            }

            // Find the difference between the AAD hashes
            if (atLengthPre > 0) {
                GCMUtil.xor(S_at, S_atPre)
            }

            // Number of cipher-text blocks produced
            val c = totalLength * 8 + 127 ushr 7

            // Calculate the adjustment factor
            val H_c = UByteArray(16)
            if (!this::exp.isInitialized) {
                exp = BasicGCMExponentiator()
                exp.init(H)
            }
            exp.exponentiateX(c, H_c)

            // Carry the difference forward
            GCMUtil.multiply(S_at, H_c)

            // Adjust the current hash
            GCMUtil.xor(S, S_at)
        }

        // Final gHASH
        val X = UByteArray(BLOCK_SIZE)
        Pack.longToBigEndian(atLength * 8, X, 0)
        Pack.longToBigEndian(totalLength * 8, X, 8)
        gHASHBlock(S, X)

        // T = MSBt(GCTRk(J0,S))
        val tag = UByteArray(BLOCK_SIZE)
        cipher.processBlock(J0, 0, tag, 0)
        GCMUtil.xor(tag, S)
        var resultLen = extra

        // We place into macBlock our calculated value for T
        macBlock = UByteArray(macSize)
        tag.copyInto(macBlock, 0, 0, macSize)
        if (forEncryption) {
            // Append T to the message
            macBlock.copyInto(out, outOffset + bufOff, 0, macSize)
            resultLen += macSize
        } else {
            // Retrieve the T value from the message and compare to calculated one
            val msgMac = UByteArray(macSize)
            bufBlock.copyInto(msgMac, 0, extra, extra + macSize)
            if (!(macBlock contentEquals msgMac)) {
                throw IllegalStateException("mac check in GCM failed")
            }
        }
        reset(false)
        return resultLen
    }

    override fun reset() {
        reset(true)
    }

    private fun reset(
        clearMac: Boolean
    ) {
        cipher.reset()

        // note: we do not reset the nonce.
        S = UByteArray(BLOCK_SIZE)
        S_at = UByteArray(BLOCK_SIZE)
        S_atPre = UByteArray(BLOCK_SIZE)
        atBlock = UByteArray(BLOCK_SIZE)
        atBlockPos = 0
        atLength = 0
        atLengthPre = 0
        counter = J0.copyOf()
        blocksRemaining = -2
        bufOff = 0
        totalLength = 0
        if (bufBlock.isNotEmpty()) {
            bufBlock.fill(0u)
        }
        if (clearMac) {
            macBlock = UByteArray(0)
        }
        if (forEncryption) {
            initialised = false
        } else {
            if (initialAssociatedText.isNotEmpty()) {
                processAADBytes(initialAssociatedText, 0, initialAssociatedText.size)
            }
        }
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        if (outBlock.size - outOff < BLOCK_SIZE) {
            throw IllegalArgumentException("Output buffer too short")
        }
        if (totalLength == 0L) {
            initCipher()
        }
        val ctrBlock = UByteArray(BLOCK_SIZE)
        getNextCTRBlock(ctrBlock)
        if (forEncryption) {
            GCMUtil.xor(ctrBlock, inBlock, inOff)
            gHASHBlock(S, ctrBlock)
            ctrBlock.copyInto(outBlock, outOff, 0, BLOCK_SIZE)
        } else {
            gHASHBlock(S, inBlock, inOff)
            GCMUtil.xor(ctrBlock, 0, inBlock, inOff, outBlock, outOff)
        }
        totalLength += BLOCK_SIZE.toLong()
        return BLOCK_SIZE
    }

    private fun processPartial(buf: UByteArray, off: Int, len: Int, out: UByteArray, outOff: Int) {
        val ctrBlock = UByteArray(BLOCK_SIZE)
        getNextCTRBlock(ctrBlock)
        if (forEncryption) {
            GCMUtil.xor(buf, off, ctrBlock, 0, len)
            gHASHPartial(S, buf, off, len)
        } else {
            gHASHPartial(S, buf, off, len)
            GCMUtil.xor(buf, off, ctrBlock, 0, len)
        }
        buf.copyInto(out, outOff, off, off + len)
        totalLength += len.toLong()
    }

    private fun gHASH(Y: UByteArray, b: UByteArray, len: Int) {
        var pos = 0
        while (pos < len) {
            val num: Int = kotlin.math.min(len - pos, BLOCK_SIZE)
            gHASHPartial(Y, b, pos, num)
            pos += BLOCK_SIZE
        }
    }

    private fun gHASHBlock(Y: UByteArray, b: UByteArray) {
        GCMUtil.xor(Y, b)
        multiplier.multiplyH(Y)
    }

    private fun gHASHBlock(Y: UByteArray, b: UByteArray, off: Int) {
        GCMUtil.xor(Y, b, off)
        multiplier.multiplyH(Y)
    }

    private fun gHASHPartial(Y: UByteArray, b: UByteArray, off: Int, len: Int) {
        GCMUtil.xor(Y, b, off, len)
        multiplier.multiplyH(Y)
    }

    private fun getNextCTRBlock(block: UByteArray) {
        if (blocksRemaining == 0) {
            throw IllegalStateException("Attempt to process too many blocks")
        }
        blocksRemaining--
        var c = 1
        c += (counter[15] and 0xFFu).toInt()
        counter[15] = c.toUByte()
        c = c ushr 8
        c += (counter[14] and 0xFFu).toInt()
        counter[14] = c.toUByte()
        c = c ushr 8
        c += (counter[13] and 0xFFu).toInt()
        counter[13] = c.toUByte()
        c = c ushr 8
        c += (counter[12] and 0xFFu).toInt()
        counter[12] = c.toUByte()
        cipher.processBlock(counter, 0, block, 0)
    }

    private fun checkStatus() {
        if (!initialised) {
            if (forEncryption) {
                throw IllegalStateException("GCM cipher cannot be reused for encryption")
            }
            throw IllegalStateException("GCM cipher needs to be initialised")
        }
    }

    companion object {
        private const val BLOCK_SIZE = 16
    }
}
