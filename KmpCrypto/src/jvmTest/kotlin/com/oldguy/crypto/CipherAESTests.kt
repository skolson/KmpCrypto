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
        val cipher = AESEngine()
        val digest = SHA256Digest()
        val key = digest.hash(CryptoTestHelp.key1, UByteArray(0))
        cipher.setKey(true, key)
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.setKey(false, key)
        val decryptedBlocks = CryptoTestHelp.process(cipher, encrypted)
        val decrypted = decryptedBlocks.slice(CryptoTestHelp.payload.size)
        assertContentEquals(CryptoTestHelp.payload, decrypted.contentBytes)

        val javaCipher = org.bouncycastle.crypto.engines.AESEngine()
        javaCipher.init(true, org.bouncycastle.crypto.params.KeyParameter(key.toByteArray()))
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        encrypted.rewind()
        assertEquals(javaEncrypted.remaining, encrypted.remaining)
        assertContentEquals(javaEncrypted.contentBytes, encrypted.contentBytes.toByteArray())
    }
}