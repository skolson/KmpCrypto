package com.oldguy.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

@ExperimentalUnsignedTypes
class SHA1DigestTests {

    @Test
    fun sha1Disgest() {
        val digest = SHA1Digest()
        val hash = digest.hash(CryptoTestHelp.payload)

        val javaDigest = org.bouncycastle.crypto.digests.SHA1Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun sha256DigestTests() {
        val digest = SHA256Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.SHA256Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun sha384DigestTests() {
        val digest = SHA384Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.SHA384Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun sha512DigestTests() {
        val digest = SHA512Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.SHA512Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun md5DigestTests() {
        val digest = MD5Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.MD5Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun md4DigestTests() {
        val digest = MD4Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.MD4Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun md2DigestTests() {
        val digest = MD2Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.MD2Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun ripemd128DigestTests() {
        val digest = RIPEMD128Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.RIPEMD128Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun ripemd160DigestTests() {
        val digest = RIPEMD160Digest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.RIPEMD160Digest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }

    @Test
    fun whirlpoolDigestTests() {
        val digest = WhirlpoolDigest()
        val hash = digest.hash(CryptoTestHelp.payload, UByteArray(0))

        val javaDigest = org.bouncycastle.crypto.digests.WhirlpoolDigest()
        javaDigest.update(CryptoTestHelp.payload.toByteArray(), 0, CryptoTestHelp.payload.size)
        val javaHash = ByteArray(digest.digestSize)
        javaDigest.doFinal(javaHash, 0)
        assertContentEquals(javaHash, hash.toByteArray())
    }
}
