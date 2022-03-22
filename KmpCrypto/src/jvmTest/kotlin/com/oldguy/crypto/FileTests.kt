package com.oldguy.crypto

import com.oldguy.common.io.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Uses a zip file (zip64 spec) as a source payload for all encryption tests, as makes content of
 * large file easy to verify.
 *
 * Currently only test is AES/GCM, need to add tests of same process using additional algorithms.
 */
@ExperimentalCoroutinesApi
class FileTests {
    private val testZipName = "ZerosZip64.zip"
    val password = "xyzAbc!@#"
    val zipSize = 5611756UL
    val encryptedSize = (5611756 + 13 + 16).toULong()

    /**
     * Encrypt a text zip64 file, using AES and GCM and a random IV. Encrypt same file with bouncy
     * castle using same key and IV, compare encrypted files to ensure size and content match.
     * Decrypt file. Verify Zip file decrypted content using Zip support.
     */
    @Test
    fun fileAesGcm() {
        val testDirectory = File("TestFiles")
        val zipFile = File(testDirectory, testZipName)
        runTest {
            val workDirectory = testDirectory.resolve("Work")
            val zipEncrypted = File(workDirectory, "$testZipName.encrypt")
            zipEncrypted.delete()
            val cipher = Cipher.build {
                parse("aes/gcm")
                key {
                    stringKey = password
                    keyDigest = Digests.SHA256
                    ivSizeMatchBlock = false
                    iv = randomIV(12)
                }
            }
            val ivContent = cipher.iv
            val source = RawFile(zipFile)
            val dest = RawFile(zipEncrypted, FileMode.Write)
            Cipher.writeInitializationVector(dest, cipher.iv)
            cipher.process(true, source, dest)
            assertTrue(zipEncrypted.exists)
            assertEquals(zipSize, zipFile.size)
            assertEquals(encryptedSize, zipEncrypted.size)

            // match to bouncycastle copy
            val bouncy = bouncyEncrypt(workDirectory, zipFile, ivContent)
            assertEquals(encryptedSize, bouncy.size)
            assertTrue(CryptoTestHelp.compare(zipEncrypted, bouncy))

            // verify IV content
            val check = RawFile(zipEncrypted)
            val ivRead = Cipher.readInitializationVector(check)
            assertContentEquals(ivContent, ivRead)
            cipher.iv = ivRead

            // decrypt
            val decryptFile = File(workDirectory, "$testZipName.decrypt.zip")
            decryptFile.delete()
            val zipDecrypted = RawFile(decryptFile, FileMode.Write)
            cipher.process(false, check, zipDecrypted)

            // Verify zip content, which is Zip64 one file expands to 5GB of zeroes. Extract not done,
            // just verify directory content (which is near end of zip file anyway).
            ZipFile(decryptFile).apply {
                open()
                val entryName = "0000"
                assertEquals(1, map.size)
                assertEquals(entryName, map.keys.first())
                val entry = map[entryName]
                    ?: throw IllegalStateException("Entry $entryName not found")
                assertEquals(entryName, entry.name)
                assertEquals(5611526UL, entry.directories.compressedSize)
                assertEquals(5368709120UL, entry.directories.uncompressedSize)
            }
            decryptFile.delete()
            bouncy.delete()
            zipEncrypted.delete()
        }
    }

    /**
     * Use same IV and algorithms to encrypt same target file using Bouncy Castle.
     * Note as part of this test a BufferReader was used solely as a larger test of BufferReader,
     * not necessary for bouncycastle use.
     */
    suspend fun bouncyEncrypt(
        workDirectory: File,
        source: File,
        ivContent: UByteArray): File {
        val eng = org.bouncycastle.crypto.engines.AESEngine()
        val javaCipher = org.bouncycastle.crypto.modes.GCMBlockCipher(eng)
        val hashKeyBytes = ByteArray(32)
        org.bouncycastle.crypto.digests.SHA256Digest().apply {
            update(password.encodeToByteArray(), 0, password.length)
            doFinal(hashKeyBytes, 0)
        }
        val hashKey = org.bouncycastle.crypto.params.KeyParameter(hashKeyBytes)
        javaCipher.init(true,
            org.bouncycastle.crypto.params.ParametersWithIV(
                hashKey,
                ivContent.toByteArray()
            )
        )
        val bouncyFile = File(workDirectory, "${source.name}.bouncy")
        bouncyFile.delete()
        val bouncyOut = RawFile(bouncyFile, FileMode.Write)
        UByteBuffer(ivContent.size + 1).apply {
            byte = ivContent.size.toUByte()
            putBytes(ivContent)
            flip()
            bouncyOut.write(this)
        }
        val zip = RawFile(source)
        val payload = ByteBuffer(4096)
        var bytesIn = 0UL
        var blocksRead = 0
        val reader = BufferReader {
            bytesIn += zip.read(payload, true)
            blocksRead++
            payload
        }
        val blockOut = ByteArray(eng.blockSize)
        var totalLength = 0
        var blk = reader.readArray(eng.blockSize)
        val bufOut = ByteBuffer(4096)
        while (blk.isNotEmpty()) {
            val length = javaCipher.processBytes(blk, 0, blk.size, blockOut, 0)
            totalLength += length
            blk = reader.readArray(eng.blockSize)
            bufOut.putBytes(blockOut, 0, length)
            if (bufOut.remaining < eng.blockSize) {
                bufOut.flip()
                bouncyOut.write(bufOut)
                bufOut.clear()
            }
        }
        val lastOut = ByteArray(eng.blockSize * 2)
        val length = javaCipher.doFinal(lastOut, 0)
        bufOut.putBytes(lastOut, 0, length)
        totalLength += length
        if (bufOut.hasRemaining) {
            bufOut.flip()
            bouncyOut.write(bufOut)
        }
        bouncyOut.close()
        zip.close()
        return bouncyFile
    }
}