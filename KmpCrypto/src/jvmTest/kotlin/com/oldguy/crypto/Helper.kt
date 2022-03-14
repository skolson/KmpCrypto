package com.oldguy.crypto

import com.oldguy.common.io.*
import kotlin.test.assertEquals
import kotlin.test.fail

@ExperimentalUnsignedTypes
class CryptoTestHelp {

    companion object {
        val payload = Charset(Charsets.UsAscii).encode("yafuygialdgjkejhr-25095672").toUByteArray()
        val stringKey = "Test1234"
        val key1 = Charset(Charsets.UsAscii).encode(stringKey).toUByteArray()

        suspend fun singleBufferTest(cipher: Cipher) {
            cipher.apply {
                val payloadBuf = UByteBuffer(payload)
                val encrypted = UByteBuffer(bufferSize.toInt())
                val decrypted = UByteBuffer(bufferSize.toInt())
                process(true, input = { payloadBuf }) {
                    if (it.remaining > encrypted.remaining)
                        fail("Encrypt too large for test. size: ${it.remaining}, cap: ${encrypted.capacity}, remaining: ${encrypted.remaining}")
                    encrypted.put(it)
                }
                encrypted.flip()
                process(false, input = { encrypted }) {
                    if (it.remaining > encrypted.remaining)
                        fail("Decrypt too large for test. size: ${it.remaining}, cap: ${decrypted.capacity}, remaining: ${decrypted.remaining}")
                    decrypted.put(it)
                }
                encrypted.flip()
                decrypted.flip()
                assertEquals(0, decrypted.compareTo(encrypted))
            }
        }

        fun process(cipher: BlockCipher, payload: UByteBuffer): UByteBuffer {
            val blockIn = UByteArray((cipher.blockSize))
            val blockOut = UByteArray((cipher.blockSize))
            val buf = UByteBuffer(1024)
            var totalLength = 0
            while (payload.remaining > 0) {
                if (payload.remaining < cipher.blockSize)
                    blockIn.fill(0u)
                payload.getBytes(blockIn)
                val length = cipher.processBlock(blockIn, 0, blockOut, 0)
                if (length > buf.remaining)
                    throw IllegalStateException("buf capacity exceeded")
                buf.putBytes(blockOut)
                totalLength += length
            }
            buf.rewind()
            return buf.slice(totalLength)
        }

        fun bouncyProcess(
            cipher: org.bouncycastle.crypto.BlockCipher,
            payload: ByteBuffer
        ): ByteBuffer {
            val blockIn = ByteArray((cipher.blockSize))
            val blockOut = ByteArray((cipher.blockSize))
            val buf = ByteBuffer(1024)
            var totalLength = 0
            while (payload.remaining > 0) {
                if (payload.remaining < cipher.blockSize)
                    blockIn.fill(0)
                payload.getBytes(blockIn)
                val length = cipher.processBlock(blockIn, 0, blockOut, 0)
                if (length > buf.remaining)
                    throw IllegalStateException("buf capacity exceeded")
                buf.putBytes(blockOut)
                totalLength += length
            }
            buf.rewind()
            return buf.slice(totalLength)
        }

        suspend fun compare(source: File, source2: File): Boolean {
            val r1 = RawFile(source)
            val r2 = RawFile(source2)
            var counter = 0UL
            val bufSize = 4096
            val b1 = ByteBuffer(bufSize)
            val b2 = ByteBuffer(bufSize)
            r1.read(b1)
            b1.flip()
            r2.read(b2)
            b2.flip()
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
                b1.clear()
                r1.read(b1)
                b1.flip()
                b2.clear()
                r2.read(b2)
                b2.flip()
            }
            r1.close()
            r2.close()
            assertEquals(source.size, source2.size)
            return diff
        }
    }
}

