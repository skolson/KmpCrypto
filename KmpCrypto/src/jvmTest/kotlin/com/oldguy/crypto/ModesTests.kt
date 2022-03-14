package com.oldguy.crypto

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

@ExperimentalCoroutinesApi
class AesTests {
    val iv8 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)
    val iv16 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 0u)

    @Test
    fun aesCbc() {
        runTest {
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
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }

    @Test
    fun aesCfbTest() {
        runTest {
            Cipher.build {
                parse("aes/cfb")
                key {
                    stringKey = CryptoTestHelp.stringKey
                    hashKeyLengthBits = 256
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
                    key = CryptoTestHelp.key1
                    ivSizeMatchBlock = false
                    iv = iv8
                    hashKeyLengthBits = 256
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
                    iv = randomIV()
                    hashKeyLengthBits = 256
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
                parse("aes/ecb")
                key {
                    key = CryptoTestHelp.key1
                    iv = iv16
                    hashKeyLengthBits = 256
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
                engine { aes() }
                mode = CipherModes.CBC
                padding = Paddings.PKCS7
                key {
                    key = CryptoTestHelp.key1
                    hashKeyLengthBits = 256
                    keyDigest = Digests.SHA256
                }
            }.apply {
                CryptoTestHelp.singleBufferTest(this)
            }
        }
    }
}
