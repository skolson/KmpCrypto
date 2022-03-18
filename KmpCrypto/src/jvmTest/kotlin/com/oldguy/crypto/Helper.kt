package com.oldguy.crypto

import com.oldguy.common.io.*
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.fail

@ExperimentalUnsignedTypes
class CryptoTestHelp {

    companion object {
        val payload = Charset(Charsets.UsAscii).encode("yafuygialdgjkejhr-25095672").toUByteArray()
        val stringKey = "Test1234"
        val key1 = Charset(Charsets.UsAscii).encode(stringKey).toUByteArray()

        fun bouncyProcess(
            cipher: org.bouncycastle.crypto.BufferedBlockCipher,
            payload: ByteBuffer
        ): ByteBuffer {
            val in1 = payload.getBytes()
            val out1 = ByteArray(in1.size * 2)
            val buf = ByteBuffer(in1.size * 2)
            val length = cipher.processBytes(in1, 0, in1.size, out1, 0)
            buf.putBytes(out1, 0, length)
            val f = cipher.doFinal(out1, 0)
            buf.putBytes(out1, 0, f)
            return buf.flip()
        }

        suspend fun compare(source: File, source2: File): Boolean {
            val r1 = RawFile(source)
            val r2 = RawFile(source2)
            var counter = 0UL
            val bufSize = 4096
            val b1 = ByteBuffer(bufSize)
            val b2 = ByteBuffer(bufSize)
            r1.read(b1, true)
            r2.read(b2, true)
            var diff = false
            while (b1.hasRemaining) {
                for (i in 0 until bufSize) {
                    if (b1.byte == b2.byte) counter++
                    else {
                        println("${source.name} comparison ${source2.name} differ starting at position: $counter")
                        diff = true
                        break
                    }
                }
                if (diff) break
                r1.read(b1, true)
                r2.read(b2, true)
            }
            r1.close()
            r2.close()
            assertEquals(source.size, source2.size)
            return diff
        }

        fun singleBufferTest(cipher: Cipher) {
            val encrypted = cipher.processOne(true, UByteBuffer(payload))
            val decrypted = cipher.processOne(false, encrypted)
            assertContentEquals(payload, decrypted.getBytes())
        }
    }
}

