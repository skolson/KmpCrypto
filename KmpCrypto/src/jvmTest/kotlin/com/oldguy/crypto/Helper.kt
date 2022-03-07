package com.oldguy.crypto

import com.oldguy.common.io.ByteBuffer
import com.oldguy.common.io.Charset
import com.oldguy.common.io.Charsets
import com.oldguy.common.io.UByteBuffer

@ExperimentalUnsignedTypes
class CryptoTestHelp {

    companion object {
        val payload = Charset(Charsets.UsAscii).encode("yafuygialdgjkejhr-25095672").toUByteArray()
        val stringKey = "Test1234"
        val key1 = Charset(Charsets.UsAscii).encode(stringKey).toUByteArray()

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

    }
}

