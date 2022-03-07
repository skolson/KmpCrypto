package com.oldguy.crypto

import com.oldguy.common.io.ByteBuffer
import com.oldguy.common.io.UByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalUnsignedTypes
class DESSmallNoBlockTest {
    @Test
    fun desSmallBlock() {
        val cipher = DESEngine()
        val digest = MD5Digest()
        val key = KeyParameter(digest.hash(CryptoTestHelp.key1, resultLen = 8))
        cipher.init(true, key)
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decryptedBlocks = CryptoTestHelp.process(cipher, encrypted)
        val decrypted = decryptedBlocks.slice(CryptoTestHelp.payload.size)
        assertContentEquals(CryptoTestHelp.payload, decrypted.contentBytes)

        val javaCipher = org.bouncycastle.crypto.engines.DESEngine()
        javaCipher.init(true, org.bouncycastle.crypto.params.KeyParameter(key.key.toByteArray()))
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        encrypted.rewind()
        assertEquals(javaEncrypted.remaining,encrypted.remaining)
        assertContentEquals(javaEncrypted.contentBytes, encrypted.contentBytes.toByteArray())
    }

    @Test
    fun des3SmallNoBlockTest() {
        val cipher = DESedeEngine()
        val digest = MD5Digest()
        val key = KeyParameter(digest.hash(CryptoTestHelp.key1, resultLen = 16))
        cipher.init(true, key)
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decryptedBlocks = CryptoTestHelp.process(cipher, encrypted)
        val decrypted = decryptedBlocks.slice(CryptoTestHelp.payload.size)
        assertContentEquals(CryptoTestHelp.payload, decrypted.contentBytes)

        val javaCipher = org.bouncycastle.crypto.engines.DESedeEngine()
        javaCipher.init(true, org.bouncycastle.crypto.params.KeyParameter(key.key.toByteArray()))
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        encrypted.rewind()
        assertEquals(javaEncrypted.remaining, encrypted.remaining)
        assertContentEquals(javaEncrypted.contentBytes, encrypted.contentBytes.toByteArray())
    }

    @Test
    fun des3_112_SmallNoBlockTest() {
        val cipher = DESedeEngine()
        val digest = MD5Digest()
        val key = KeyParameter(digest.hash(CryptoTestHelp.key1, resultLen = 24))
        cipher.init(true, key)
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decryptedBlocks = CryptoTestHelp.process(cipher, encrypted)
        val decrypted = decryptedBlocks.slice(CryptoTestHelp.payload.size)
        assertContentEquals(CryptoTestHelp.payload, decrypted.contentBytes)

        val javaCipher = org.bouncycastle.crypto.engines.DESedeEngine()
        javaCipher.init(true, org.bouncycastle.crypto.params.KeyParameter(key.key.toByteArray()))
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
