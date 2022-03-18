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
        val desKey = byteArrayOf(18, -49, 48, -119, -112, -21, 99, -90).toUByteArray()

        val javaCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher(org.bouncycastle.crypto.engines.DESEngine())
        val hashKey = org.bouncycastle.crypto.params.KeyParameter(desKey.toByteArray())
        javaCipher.init(true, hashKey)
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        val cipher = Cipher.build {
            padding = Paddings.PKCS7
            engine { des() }
            key {
                key = desKey
            }
        }
        val encrypted = cipher.processOne(true, UByteBuffer(CryptoTestHelp.payload))
        val decrypted = cipher.processOne(false, encrypted)
        assertContentEquals(CryptoTestHelp.payload, decrypted.getBytes())
        encrypted.flip()
        assertEquals(javaEncrypted.remaining, encrypted.remaining)
        assertContentEquals(javaEncrypted.getBytes(), encrypted.getBytes().toByteArray())
    }

    @Test
    fun des3SmallNoBlockTest() {
        val desKey = UByteArray(16)
        SecureRandom().nextBytes(desKey)
        val cipher = Cipher.build {
            padding = Paddings.PKCS7
            engine { _3des() }
            key {
                key = desKey
            }
        }
        val encrypted = cipher.processOne(true, UByteBuffer(CryptoTestHelp.payload))
        val decrypted = cipher.processOne(false, encrypted)
        assertContentEquals(CryptoTestHelp.payload, decrypted.getBytes())

        val javaCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher(org.bouncycastle.crypto.engines.DESedeEngine())
        val hashKey = org.bouncycastle.crypto.params.KeyParameter(desKey.toByteArray())
        javaCipher.init(true, hashKey)
        val javaEncrypted =
            CryptoTestHelp.bouncyProcess(
                javaCipher,
                ByteBuffer(CryptoTestHelp.payload.toByteArray())
            )

        encrypted.flip()
        assertEquals(javaEncrypted.remaining, encrypted.remaining)
        assertContentEquals(javaEncrypted.getBytes(), encrypted.getBytes().toByteArray())
    }

    @Test
    fun des3_112_SmallNoBlockTest() {
        val desKey = UByteArray(24)
        SecureRandom().nextBytes(desKey)
        val cipher = Cipher.build {
            padding = Paddings.PKCS7
            engine { _3des112() }
            key {
                key = desKey
            }
        }
        val encrypted = cipher.processOne(true, UByteBuffer(CryptoTestHelp.payload))
        val decrypted = cipher.processOne(false, encrypted)
        assertContentEquals(CryptoTestHelp.payload, decrypted.getBytes())

        val javaCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher(org.bouncycastle.crypto.engines.DESedeEngine())
        val hashKey = org.bouncycastle.crypto.params.KeyParameter(desKey.toByteArray())
        javaCipher.init(true, hashKey)
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
