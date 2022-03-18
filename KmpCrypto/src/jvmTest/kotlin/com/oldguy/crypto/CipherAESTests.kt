package com.oldguy.crypto

import com.oldguy.common.io.ByteBuffer
import com.oldguy.common.io.UByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalUnsignedTypes
class AesSmallNoBlockTest{

    @Test
    fun aesSmallBlock() {
        val cipher = Cipher.build {
            padding = Paddings.PKCS7
            engine { aes() }
            key {
                keyDigest = Digests.SHA256
                key = CryptoTestHelp.key1
            }
        }
        val encrypted = cipher.processOne(true, UByteBuffer(CryptoTestHelp.payload))
        val decrypted = cipher.processOne(false, encrypted)
        assertContentEquals(CryptoTestHelp.payload, decrypted.getBytes())

        val javaCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher(org.bouncycastle.crypto.engines.AESEngine())
        val hashKeyBytes = ByteArray(32)
        org.bouncycastle.crypto.digests.SHA256Digest().apply {
            update(CryptoTestHelp.key1.toByteArray(), 0, CryptoTestHelp.key1.size)
            doFinal(hashKeyBytes, 0)
        }
        val hashKey = org.bouncycastle.crypto.params.KeyParameter(hashKeyBytes)
        javaCipher.init(true, hashKey)
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        encrypted.rewind()
        assertEquals(javaEncrypted.remaining, encrypted.remaining)
        assertContentEquals(javaEncrypted.getBytes(), encrypted.getBytes().toByteArray())
    }
}