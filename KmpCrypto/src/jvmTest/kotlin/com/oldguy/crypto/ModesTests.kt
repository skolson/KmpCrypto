package com.oldguy.crypto

import kotlin.test.Test

class AesTests {
    val iv8 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
    val iv16 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)

    @Test
    fun aesCbc() {
        Cipher.build {
            engine { aes() }
            mode = CipherModes.CBC
            padding = Paddings.PKCS7
            key {
                stringKey = CryptoTestHelp.stringKey
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            CryptoTestHelp.smallBufTest(this)
        }
    }

    @Test
    fun aesCfbTest() {
        Cipher.build {
            parse("aes/cfb")
            key {
                stringKey = CryptoTestHelp.stringKey
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            CryptoTestHelp.smallBufTest(this)
        }
    }

    @Test
    fun aesCcmTest() {
        Cipher.build {
            parse("aes/ccm")
            key {
                key = CryptoTestHelp.key1
                iv = iv8
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            CryptoTestHelp.smallBufTest(this)
        }
    }

    @Test
    fun aesGcmTest() {
        Cipher.build {
            parse("aes/gcm")
            key {
                key = CryptoTestHelp.key1
                iv = randomIV()
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            CryptoTestHelp.smallBufTest(this)
        }
    }

    @Test
    fun aesEcbTest() {
        Cipher.build {
            parse("aes/ecb")
            key {
                key = CryptoTestHelp.key1
                iv = iv16
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            CryptoTestHelp.smallBufTest(this)
        }
    }

    @Test
    fun aesCbcPKCSTest() {
        Cipher.build {
            engine { aes() }
            mode = CipherModes.CBC
            padding = Paddings.PKCS7
            key {
                key = CryptoTestHelp.key1
                hashKeyLengthBits = 256
                keyDigest = Digests.SHA256
            }
        }.apply {
            CryptoTestHelp.smallBufTest(this)
        }
    }
}
