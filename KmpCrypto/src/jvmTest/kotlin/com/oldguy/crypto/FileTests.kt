package com.oldguy.crypto

import com.oldguy.common.io.*
import com.oldguy.common.toHex
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@ExperimentalCoroutinesApi
class FileTests {
    private val testZipName = "ZerosZip64.zip"
    val password = "xyzAbc!@#"

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
                    hashKeyLengthBits = 256
                    macSize = 128
                    iv = randomIV()
                }
            }
            val ivContent = cipher.keyConfiguration.iv
            val source = RawFile(zipFile)
            val dest = RawFile(zipEncrypted, FileMode.Write).apply {
                UByteBuffer(cipher.keyConfiguration.ivSize + 1).apply {
                    byte = cipher.engine.ivSize.toUByte()
                    putBytes(cipher.keyConfiguration.iv)
                    flip()
                    write(this)
                }
            }
            cipher.process(true, source, dest)
            assertTrue(zipEncrypted.exists)

            val b = bouncyEncrypt(workDirectory, zipFile, ivContent)
            assertTrue(CryptoTestHelp.compare(zipEncrypted, b))

            val check = RawFile(zipEncrypted)
            val buf = ByteBuffer(1)
            assertEquals(1u, check.read(buf))
            buf.flip()
            val length = buf.byte.toUInt()
            assertEquals(12u, length)
            val ivBuf = UByteBuffer(length.toInt())
            assertEquals(length, check.read(ivBuf))
            assertContentEquals(ivContent, ivBuf.flip().getBytes())

            val decryptFile = File(workDirectory, "$testZipName.decrypt.zip")
            decryptFile.delete()
            val zipDecrypted = RawFile(decryptFile, FileMode.Write)
            cipher.process(false, check, zipDecrypted)
        }
    }

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
            payload.clear()
            bytesIn += zip.read(payload)
            blocksRead++
            payload.flip()
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