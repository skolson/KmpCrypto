package com.oldguy.crypto

import com.oldguy.common.io.UByteBuffer
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

@ExperimentalUnsignedTypes
class AesTests {

    @Test
    fun aesCbcV2() {
        CipherV2.make {
            engine { aes() }
            mode = CipherModes.CBC
            key {
                stringKey = CryptoTestHelp.stringKey
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            val payload = UByteBuffer(CryptoTestHelp.payload)
            var encrypted = UByteBuffer(this.engineParm.blockSize)
            var decrypted = UByteBuffer(this.engineParm.blockSize)
            runBlocking {
                process(true, input = { payload }) {
                    encrypted = it
                }
                process(false, input = { encrypted }) {
                    decrypted = it
                }
                assertEquals(0, decrypted.compareTo(encrypted))
            }
        }
    }

    @Test
    fun aesCbc() {
        val cipher = Cipher.makeCipher {
            engine { aes() }
            mode = CipherModes.CBC
        }
        val key = Cipher.initializeKey(cipher) {
            key = CryptoTestHelp.key1
            forEncryption = true
            hashKeyLengthBits = 256
            keyDigest = Digests.SHA256
        }
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decrypted = CryptoTestHelp.process(cipher, encrypted)
        assertEquals(0, decrypted.compareTo(encrypted))
    }

    @Test
    fun aesCfbTest() {
        val cipher = Cipher.makeCipher {
            parse("aes/cfb")
        }
        val key = Cipher.initializeKey(cipher) {
            key = CryptoTestHelp.key1
            forEncryption = true
            hashKeyLengthBits = 256
            keyDigest = Digests.SHA256
        }
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decrypted = CryptoTestHelp.process(cipher, encrypted)
        assertEquals(0, decrypted.compareTo(encrypted))
    }

    @Test
    fun aesCcmTest() {
        val cipher = Cipher.makeCipher {
            parse("aes/ccm")
        }
        val key = Cipher.initializeKey(cipher) {
            key = CryptoTestHelp.key1
            iv = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
            forEncryption = true
            hashKeyLengthBits = 256
            keyDigest = Digests.SHA256
        }
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decrypted = CryptoTestHelp.process(cipher, encrypted)
        assertEquals(0, decrypted.compareTo(encrypted))
    }

    @Test
    fun aesGcmTest() {
        val cipher = Cipher.makeCipher {
            parse("aes/gcm")
        }
        val key = Cipher.initializeKey(cipher) {
            key = CryptoTestHelp.key1
            iv = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
            forEncryption = true
            hashKeyLengthBits = 256
            keyDigest = Digests.SHA256
        }
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decrypted = CryptoTestHelp.process(cipher, encrypted)
        assertEquals(0, decrypted.compareTo(encrypted))
    }

    @Test
    fun aesEcbTest() {
        val cipher = Cipher.makeCipher {
            parse("aes/ecb")
        }
        val key = Cipher.initializeKey(cipher) {
            key = CryptoTestHelp.key1
            iv = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
            forEncryption = true
            hashKeyLengthBits = 256
            keyDigest = Digests.SHA256
        }
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decrypted = CryptoTestHelp.process(cipher, encrypted)
        assertEquals(0, decrypted.compareTo(encrypted))
    }

    @Test
    fun aesCbcPKCSTest() {
        val cipher = Cipher.makeCipher {
            engine { aes() }
            mode = CipherModes.CBC
            padding = Paddings.PKCS7
        }
        val key = Cipher.initializeKey(cipher) {
            key = CryptoTestHelp.key1
            forEncryption = true
            hashKeyLengthBits = 256
            keyDigest = Digests.SHA256
        }
        val encrypted = CryptoTestHelp.process(cipher, UByteBuffer(CryptoTestHelp.payload))

        cipher.init(false, key)
        val decrypted = CryptoTestHelp.process(cipher, encrypted)
        assertEquals(0, decrypted.compareTo(encrypted))
    }
}
