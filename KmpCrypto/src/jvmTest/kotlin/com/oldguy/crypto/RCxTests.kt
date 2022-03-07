package com.oldguy.crypto

import com.oldguy.common.io.ByteBuffer
import com.oldguy.common.io.UByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * RC4Engine is not a block cipher, so test logic is unique to RC4
 */
@ExperimentalUnsignedTypes
class RC4Tests {
    @Test
    fun rc4Small() {
        val cipher = RC4Engine()
        val key = KeyParameter(CryptoTestHelp.key1)
        cipher.init(true, key)
        val encrypted = UByteArray(CryptoTestHelp.payload.size)
        val length = cipher.processBytes(
            CryptoTestHelp.payload,
            0, CryptoTestHelp.payload.size,
            encrypted, 0
        )

        cipher.init(false, key)
        val decrypted = UByteArray(CryptoTestHelp.payload.size)
        val length2 = cipher.processBytes(
            encrypted,
            0, encrypted.size,
            decrypted, 0
        )
        assertEquals(CryptoTestHelp.payload.size, length)
        assertEquals(CryptoTestHelp.payload.size, length2)
        assertContentEquals(CryptoTestHelp.payload, decrypted)

        val javaCipher = org.bouncycastle.crypto.engines.RC4Engine()
        javaCipher.init(
            true,
            org.bouncycastle.crypto.params.KeyParameter(CryptoTestHelp.key1.toByteArray())
        )
        val javaEncrypted = ByteArray(CryptoTestHelp.payload.size)
        val bytes = javaCipher.processBytes(
            CryptoTestHelp.payload.toByteArray(),
            0, CryptoTestHelp.payload.size,
            javaEncrypted, 0
        )
        assertEquals(javaEncrypted.size, bytes)
        assertContentEquals(javaEncrypted, encrypted.toByteArray())
    }

    @Test
    fun rc4SmallBlockTest() {
        val cipher = BlockCipherAdapter(RC4Engine())
        val key = KeyParameter(CryptoTestHelp.key1)
        cipher.init(true, key)
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decryptedBlocks = CryptoTestHelp.process(cipher, encrypted)
        val decrypted = decryptedBlocks.slice(CryptoTestHelp.payload.size)
        assertContentEquals(CryptoTestHelp.payload, decrypted.contentBytes)
    }

    @Test
    fun rc2SmallNoBlockTest() {
        val cipher = RC2Engine()
        val key = CryptoTestHelp.key1
        cipher.setKey(true, key)
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.setKey(false, key)
        val decryptedBlocks = CryptoTestHelp.process(cipher, encrypted)
        val decrypted = decryptedBlocks.slice(CryptoTestHelp.payload.size)
        assertContentEquals(CryptoTestHelp.payload, decrypted.contentBytes)

        val javaCipher = org.bouncycastle.crypto.engines.RC2Engine()
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