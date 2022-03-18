package com.oldguy.crypto

import com.oldguy.common.io.ByteBuffer
import com.oldguy.common.io.Charset
import com.oldguy.common.io.Charsets
import com.oldguy.common.io.UByteBuffer
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals

@ExperimentalCoroutinesApi
class AesTests {
    val iv8 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
    val iv16 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
    val payload = "any stuff in here 12345678"
    val keyBytes = byteArrayOf(0,1,2,3,4,5,6,7,8,9,0x7f,0x55)
    val payloadBytes = Charset(Charsets.Utf8).encode(payload)

    @Test
    fun aesCbc() {
        runTest {
            Cipher.build {
                mode = CipherModes.CBC
                padding = Paddings.PKCS7
                engine { aes() }
                key {
                    key = keyBytes.toUByteArray()
                    keyDigest = Digests.SHA256
                }
            }.apply {
                val encrypted = processOne(true, UByteBuffer(payloadBytes.toUByteArray()))

                val javaCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher(
                    org.bouncycastle.crypto.modes.CBCBlockCipher(
                    org.bouncycastle.crypto.engines.AESEngine()
                    ))
                val hashKeyBytes = ByteArray(32)
                org.bouncycastle.crypto.digests.SHA256Digest().apply {
                    update(keyBytes, 0, keyBytes.size)
                    doFinal(hashKeyBytes, 0)
                }
                val hashKey = org.bouncycastle.crypto.params.KeyParameter(hashKeyBytes)
                javaCipher.init(true, hashKey)
                val javaEncrypted =
                    CryptoTestHelp.bouncyProcess(
                        javaCipher,
                        ByteBuffer(payloadBytes)
                    )

                val jb = javaEncrypted.getBytes()
                val eb = encrypted.getBytes().toByteArray()
                assertContentEquals(jb, eb)

                val decrypted = processOne(false, encrypted.flip())
                assertContentEquals(payloadBytes, decrypted.getBytes().toByteArray())
            }
        }
    }

    @Test
    fun aesCfbTest() {
        runTest {
            Cipher.build {
                parse("aes/cfb/pkcs7")
                key {
                    stringKey = CryptoTestHelp.stringKey
                    keyDigest = Digests.SHA256
                }
            }.apply {
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }

    @Test
    fun aesCcmTest() {
        runTest {
            Cipher.build {
                parse("aes/ccm")
                key {
                    key = keyBytes.toUByteArray()
                    authenticatedEncryptionAssociatedData(16, iv8)
                    keyDigest = Digests.SHA256
                }
            }.apply {
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }

    @Test
    fun aesGcmTest() {
        runTest {
            Cipher.build {
                parse("aes/gcm")
                key {
                    key = CryptoTestHelp.key1
                    authenticatedEncryptionAssociatedData(16, iv8)
                    keyDigest = Digests.SHA256
                }
            }.apply {
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }

    @Test
    fun aesEcbTest() {
        runTest {
            Cipher.build {
                parse("aes/ecb/pkcs7")
                key {
                    key = CryptoTestHelp.key1
                    iv = iv16
                    keyDigest = Digests.SHA256
                }
            }.apply {
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }

    @Test
    fun aesCbcPKCSTest() {
        runTest {
            Cipher.build {
                mode = CipherModes.CBC
                padding = Paddings.PKCS7
                engine { aes() }
                key {
                    key = CryptoTestHelp.key1
                     keyDigest = Digests.SHA256
                }
            }.apply {
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }
}
