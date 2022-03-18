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
        val cipher = Cipher.build {
            engine { rc4() }
            key {
                key = CryptoTestHelp.key1
            }
        }
        val encrypted = cipher.processOne(true, UByteBuffer(CryptoTestHelp.payload))

        val decryptedBytes = cipher.processOne(false, encrypted).getBytes()
        val encryptedBytes = encrypted.flip().getBytes()

        assertEquals(CryptoTestHelp.payload.size, encryptedBytes.size)
        assertEquals(CryptoTestHelp.payload.size, decryptedBytes.size)
        assertContentEquals(CryptoTestHelp.payload, decryptedBytes)

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
        assertContentEquals(javaEncrypted, encryptedBytes.toByteArray())
    }

    @Test
    fun rc2SmallNoBlockTest() {
        val cipher = Cipher.build {
            padding = Paddings.PKCS7
            engine { rc2() }
            key {
                key = CryptoTestHelp.key1
            }
        }
        val encrypted = cipher.processOne(true, UByteBuffer(CryptoTestHelp.payload))
        val decrypted = cipher.processOne(false, encrypted)

        assertContentEquals(CryptoTestHelp.payload, decrypted.getBytes())

        val javaCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher(org.bouncycastle.crypto.engines.RC2Engine())
        javaCipher.init(true, org.bouncycastle.crypto.params.KeyParameter(CryptoTestHelp.key1.toByteArray()))
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        encrypted.flip()
        assertEquals(javaEncrypted.remaining, encrypted.remaining)
        assertContentEquals(javaEncrypted.getBytes(), encrypted.getBytes().toByteArray())
    }
}