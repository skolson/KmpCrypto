package com.oldguy.crypto

import com.oldguy.common.io.*

/**
 * These are the supported chaining modes that can be applied to any of the selected engines
 */
enum class CipherModes { None, CBC, CFB, CCM, GCM, ECB }  // PCBC, OFB

/**
 * Available padding schemes.
 */
enum class Paddings { None, PKCS7 }   // SSL3Padding, ISO10126Padding

/**
 * These are the supported Digests that can be used in the key builder any time a key needs to
 * be hashed to a specific length.
 */
enum class Digests {
    None, SHA1, SHA256, SHA384, SHA512, MD5, MD4, MD2,
    RIPEMD128, RIPEMD160, Whirlpool
}

/**
 * See [build] companion function to configure and build a cipher for use in
 * encryption/descryption operations.
 *
 * A DSL-like syntax offers flexibility for setting up a cipher and its key.
 * CipherV2.build {
 *     engine { aes() }
 *     mode = CipherModes.CBC
 *     padding = Paddings.PKCS7
 *     key {
 *         stringKeyCharset = Charset(Charsets.Utf16le)
 *         stringKey = "SomeKey"
 *         keyDigest = Digests.SHA256
 *     }
 * }
 * configures a cipher with AES, CBC chaining, and PKCS7 padding. It also sets the key to a string
 * value encoded with UTF-16 Little Endian encoding.
 *
 * Note that if a Cipher instance is created without using the DSL syntax, then it is created with
 * an empty key configuration that is typically not useful until it is set. Be sure to invoke the
 * [key] function to set the desired key-related parameters BEFORE using any of the [process] or
 * [processOne] methods.
 */
class Cipher {

    /**
     * Typically use the DSL to choose an engine. Default is AES
     */
    var engine: BlockCipher = AESEngine()

    var keyConfiguration = KeyConfiguration()

    /**
     * Contains all the parameters related to building the key used for encryption/decryption. Must
     * be set using the [key] function.  Default is a zero byte key with no IV, no other additional
     * info (mac size, nonce, additional data, etc all zero or empty)
     */
    var parameters = keyConfiguration.build(this)
        private set

    /**
     * Size in bytes of buffers used in the [process] function. Controls the maximum number of bytes
     * processed in any one operation.  If this needs to be changed, keep it a multiple of 512.
     */
    var bufferSize = 4096u

    /**
     * Any of the algorithm modes in [CipherModes] can be used with any engine. Default is none.
     * If changing this, change it BEFORE calling the [engine] function
     */
    var mode = CipherModes.None

    /**
     * this parm is specific to CFB chaining mode and is ignored otherwise.  it defaults to 128
     * as the most commonly used value, or can be smaller in multiples of 8.
     */
    var cfbBitSize = 128

    /**
     * Any of the valid padding modes can be applied to any engine and chaining.  Default is none.
     * If changing this, change it BEFORE calling the [engine] function
     */
    var padding = Paddings.None

    var debug = false

    /**
     * Property for changing key before invoking [process] or [processOne], but
     * retaining all other previously set [KeyConfiguration] parameters. Use the [key] function
     * to configure a full key configuration using more than just the key bytes.
     *
     * Note each set() invocation creates a new [parameters] instance with the updated key bytes.
     * If an empty key array is used with set, an exception is thrown.
     */
    var key: UByteArray
        get() = keyConfiguration.key
        set(value) {
            if (value.isEmpty())
                throw IllegalArgumentException("Zero byte keys are invalid")
            val c = this
            keyConfiguration.apply {
                key = value
                parameters = build(c)
            }
        }

    private var processedCount = 0UL
    private lateinit var outBlock: UByteBuffer

    /**
     * Generate a Random IV of the specified size in bytes, using the specified SecureRandom class
     * as a source.
     * @param size length of initialization vector in bytes. Default is specified by the configured
     * engine, so the default should typically be sufficient.
     * @param randomSource Uses the [SecureRandom] source to create a cryptographic-quality random set of
     * bytes. Default uses SecureRandomMechanism.Hash_DRBG and SecureRandomAlgorithm.SHA512
     */
    fun randomIV(
        size: Int = engine.ivSize,
        randomSource: SecureRandom = SecureRandom()
    ): UByteArray {
        return UByteArray(size).apply {
            randomSource.nextBytes(this)
        }
    }

    /**
     * This is a convenience method for compatibility with [javax.crypto.Cipher.getInstance(String)]
     *
     * Parse a specification string for Engine, chaining, and padding. Format of string is:
     * "<engine>/<chaining>/<padding>, where engine is required, but chaining and padding are optional.
     *
     * Format is from javax.crypto.Cipher.getInstance(...)
     *
     * @param specification uses forward slash as a delimiter, and is case-insensitive
     * Engine is required, can be one of these values:
     *      AES, RC2, RC4, DES, 3DES, 3DES112
     * Mode, if present, can be one of these values:
     *      CBC, CFB, CCM, GCM, ECB
     * Padding, if present, can be one of these values:
     *      PKCS5, PKCS7
     * Note that PKCS5 and PKCS7 do the exact same result.
     */
    fun parse(specification: String) {
        val error = "Can't parse specification: $specification"
        if (specification.isEmpty()) throw IllegalArgumentException(error)
        val tokens = specification.uppercase().split('/')
        if (tokens.isEmpty() || tokens.size > 3 || tokens[0].isEmpty())
            throw IllegalArgumentException(error)
        val e = Engine()
        engine = when (tokens[0]) {
            "AES" -> e.aes()
            "RC2" -> e.rc2()
            "RC4" -> e.rc4()
            "DES" -> e.des()
            "3DES" -> e._3des()
            "3DES112" -> e._3des112()
            else -> throw IllegalArgumentException("Engine token: ${tokens[0]} is unsupported")
        }
        if (tokens.size > 1) {
            mode = when (tokens[1]) {
                "CBC" -> CipherModes.CBC
                "CFB" -> CipherModes.CFB
                "CCM" -> CipherModes.CCM
                "GCM" -> CipherModes.GCM
                "ECB" -> CipherModes.ECB
                else -> throw IllegalArgumentException("Mode token: ${tokens[1]} is unsupported")
            }
        } else
            mode = CipherModes.None
        if (tokens.size == 3) {
            padding = when (tokens[2].uppercase()) {
                "PKCS5", "PKCS7" -> Paddings.PKCS7
                "NONE" -> Paddings.None
                else -> throw IllegalArgumentException("Padding token: ${tokens[2]} is unsupported")
            }
        } else
            padding = Paddings.None
        build()
    }

    /**
     * These functions supply the available engine. Note that a BufferedBlockCipher is usable with partial
     * blocks on PGP, CFB, OFB, OpenPGP, SIC, GCTR and so can be wrapped here when/if those are supported
     */
    class Engine {
        fun aes(): BlockCipher {
            return AESEngine()
        }

        fun rc2(): BlockCipher {
            return RC2Engine()
        }

        fun rc4(): BlockCipher {
            return BufferedBlockCipher(BlockCipherAdapter(RC4Engine()), true)
        }

        fun des(): BlockCipher {
            return DESEngine()
        }

        fun _3des(): BlockCipher {
            return DESedeEngine()
        }

        fun _3des112(): BlockCipher {
            return DESedeEngine(true)
        }
    }

    /**
     * Sets the configured engine from the results of the lambda. Then uses the mode and padding
     * values to configure the engine in this Cipher instance
     * @param arg lambda that invokes one of the [Engine] functions to set an engine
     */
    inline fun engine(arg: Engine.() -> BlockCipher) {
        engine = Engine().arg()
        build()
    }

    /**
     * DSL syntax to set the key configuration parameters. This function must be used to set any
     * non-trivial key configuration. If left to the default, only the [key] UByteArray parameter
     * will be used, and the UByteArray must be manually set to something not empty before invoking
     * [process] or [processOne].
     */
    fun key(arg: KeyConfiguration.() -> Unit) {
        val c = this
        keyConfiguration = KeyConfiguration()
            .apply {
                ivSize = engine.blockSize.toUInt()
                arg()
                parameters = build(c)
            }
    }

    /**
     * Builds a Cipher instance
     */
    fun build(): Cipher {
        engine.apply {
            val eng = when (mode) {
                CipherModes.None -> this
                CipherModes.CBC -> CBCBlockCipher(this)
                CipherModes.CFB -> CFBBlockCipher(this, cfbBitSize)
                CipherModes.CCM -> CCMBlockCipher(this)
                CipherModes.GCM -> GCMBlockCipher(this)
                CipherModes.ECB -> ECBBlockCipher(this)
            }
            engine = when (padding) {
                Paddings.None -> eng
                Paddings.PKCS7 -> PaddedBufferedBlockCipher(eng)
            }
        }
        return this
    }

    /**
     * Initializes the configured Cipher, then repeatedly calls the input function to get input data.
     * Process ends when input is called with an empty (!hasRemaining) buffer.  Output is called
     * once for each processed block, with a buffer positioned at zero and remaining = bytes produced.
     * @param encrypt true if input data is being encrypted. False if input data is being decrypted.
     * @param input lambda should provide buffers until all input data is processed. Note that every
     * block cipher has a block size, and that the incoming buffers should be a non zero multiple of
     * that block size in length until the last bloc, which can be any size.
     * @param output buffer is of [bufferSize] size. lambda is invoked once each time the buffer is
     * full (or close to it). Buffer is flipped before [output] is called, so the buffer's remaining
     * value is always the number of bytes to retrieve.
     * @return total number of bytes sent to output function
     */
    suspend fun process(
        encrypt: Boolean,
        input: suspend () -> UByteBuffer,
        output: suspend (buffer: UByteBuffer) -> Unit
    ): ULong {
        processedCount = 0u
        val eng = engine
        eng.apply {
            init(encrypt, parameters)
            var inBuffer = input()
            outBlock = UByteBuffer(bufferSize.toInt() * 2)
            while (inBuffer.hasRemaining) {
                output(processOneBuffer(inBuffer))
                inBuffer = input()
            }
            outBlock.clear()
            outBlock.putBytes(finishProcess())
            outBlock.flip()
            if (outBlock.hasRemaining) output(outBlock)
        }
        return processedCount
    }

    private fun finishProcess():UByteArray {
        val eng = engine
        eng.apply {
            val rem = 0
            var finalBytes = UByteArray(blockSize * 2)
            val last = when (this) {
                is AEADBlockCipher -> {
                    val sz = getOutputSize(rem)
                    if (sz > finalBytes.size) finalBytes = UByteArray(sz)
                    doFinal(finalBytes, 0)
                }
                is PaddedBufferedBlockCipher -> {
                    val sz = getOutputSize(rem)
                    if (sz > finalBytes.size) finalBytes = UByteArray(sz)
                    doFinal(finalBytes, 0)
                }
                is BufferedBlockCipher -> {
                    val sz = getOutputSize(rem)
                    if (sz > finalBytes.size) finalBytes = UByteArray(sz)
                    doFinal(finalBytes, 0)
                }
                else -> 0
            }
            processedCount += last.toUInt()
            return if (last > 0)
                finalBytes.sliceArray(0 until last)
            else
                UByteArray(0)
        }
    }

    private fun processOneBuffer(inBuffer: UByteBuffer): UByteBuffer {
        val eng = engine
        eng.apply {
            val b = inBuffer.getBytes().toUByteArray()
            processedCount += when (this) {
                is AEADBlockCipher -> {
                    val r = processBytes(b, 0, b.size, outBlock.contentBytes, 0)
                    outBlock.positionLimit(0, r)
                    r
                }
                is PaddedBufferedBlockCipher -> {
                    val r = processBytes(b, 0, b.size, outBlock.contentBytes, 0)
                    outBlock.positionLimit(0, r)
                    r
                }
                is BufferedBlockCipher ->{
                    val r = processBytes(b, 0, b.size, outBlock.contentBytes, 0)
                    outBlock.positionLimit(0, r)
                    r
                }
                else -> {
                    if (b.size % blockSize > 0)
                        throw IllegalArgumentException("Input buffer size: ${b.size} not multiple of blockSize: $blockSize")
                    var offset = 0
                    val blockOut = UByteArray(blockSize)
                    while (offset < b.size) {
                        engine.processBlock(b, offset, blockOut, 0)
                        outBlock.putBytes(blockOut)
                        offset += blockSize
                    }
                    outBlock.flip()
                    b.size
                }
            }.toUInt()
            return outBlock
        }
    }

    /**
     * Decrypt one inBuffer that contains entire payload to be encrypted/decrypted. Does same as
     * [process] function using one and only one input buffer. Also does not require coroutine.
     * @param encrypt true if input data is being encrypted. False if input data is being decrypted.
     * @param inBuffer remaining bytes in buffer are processed as entire payload.
     * @return processed output
     */
    fun processOne(encrypt: Boolean, inBuffer: UByteBuffer): UByteBuffer {
        val eng = engine
        eng.apply {
            init(encrypt, parameters)
            outBlock = UByteBuffer(inBuffer.capacity + (blockSize * 2))
            return processOneBuffer(inBuffer).apply {
                position = limit
                limit = capacity
                putBytes(finishProcess())
            }.flip()
        }
    }

    /**
     * Convenience method for encrypting/decrypting a source file to a destination file. For decryption,
     * if the inFile has an initialization vector, it must be read before calling this function,
     * so that the current position of the inFile is the start of encrypted data. For encryption, any
     * initialization vector should already have been written before calling this.
     * @param encrypt true for encryption, false for decryption
     * @param inFile input data file, see note above for IV handling
     * @param outFile output data file, see note above for IV handling
     */
    suspend fun process(
        encrypt: Boolean,
        inFile: RawFile,
        outFile: RawFile
    ): ULong {
        inFile.blockSize = engine.blockSize.toUInt()
        val buf = UByteBuffer(bufferSize.toInt())
        try {
            return process(encrypt,
                input = {
                    inFile.read(buf, true)
                    buf
                }
            ) {
                outFile.write(it)
            }
        } finally {
            outFile.close()
            inFile.close()
        }
    }

    /**
     * Optional convenience function. Reads an Initialization Vector (IV) from the file. Typically
     * the IV is at the start of the file, i.e. position 0.  If the
     * file used [writeInitializationVector] to write the IV, then the length of the IV written is
     * in the first byte of the file.
     * The number of bytes is read into a UByteArray.
     * The result is returned, and is also retained in [keyConfiguration].
     * Note: any prior value in keyConfiguration.iv is overwritten.
     *
     * If the file has an IV with no length byte, then specify the length to be retrieved in the second
     * argument.
     *
     * @param encryptedFile that has an IV at the current position, typically position 0.
     * On return the file position will be just after the IV read, if any.
     * @param length optional length of IV to read. If -1 (default), then assumes first byte of file is IV
     * length, see [writeInitializationVector]. if 0, then no IV is read and an empty IV array is
     * returned. If length > 0, then a byte array is returned
     * containing the IV. If file does not contain sufficient bytes, an exception is thrown.
     * @return UByteArray with the IV value, which is also retained in keyConfiguration.iv.
     */
    suspend fun readInitializationVector(encryptedFile: RawFile, length: Int = -1): UByteArray {
        if (length == 0) {
            keyConfiguration.iv = UByteArray(0)
        } else {
            var l = length.toUInt()
            if (length < 0) {
                encryptedFile.readBuffer(1u).apply {
                    if (remaining != 1) throw IllegalStateException("Could not read length byte: $this")
                    l = byte.toUInt()
                }
            }
            val pos = encryptedFile.position
            encryptedFile.readUBuffer(l).apply {
                if (capacity.toUInt() != l)
                    throw IllegalStateException("Expected $l bytes at position $pos, found $capacity")
                keyConfiguration.iv = getBytes()
            }
        }
        return keyConfiguration.iv
    }

    /**
     * Optional convenience function. Writes the IV, typically to the start of a file (position 0).
     * Writes the content of the iv property of [keyConfiguration] at the current file position. File must
     * be write mode or an exception is thrown
     * @param encyptedFile typically a new file and the IV is the first content written. If file is not
     * write mode, an exception is thrown
     * @param writeLength if true, the first byte written is the length of the IV in [keyConfiguration].
     * If false, just the IV is written.
     * @return number of bytes written to file.
     */
    suspend fun writeInitializationVector(encyptedFile: RawFile, writeLength: Boolean = true): UInt {
        val l = if (writeLength) 1 else 0
        UByteBuffer(keyConfiguration.iv.size + l).apply {
            if (writeLength)
                byte = keyConfiguration.iv.size.toUByte()
            putBytes(keyConfiguration.iv)
            flip()
            println("Write IV: $contentBytes")
            encyptedFile.write(this)
            return capacity.toUInt()
        }
    }

    companion object {
        fun build(lambda: Cipher.() -> Unit): Cipher {
            return Cipher()
                .apply(lambda)
        }
    }

    /**
     * This builder assists with building key info for a particular engine.
     * It is fairly easy currently to configure a key that is not consistent with the associated cipher.
     * If a key is built without the correct options, the engine will throw an IllegalArgumentException
     * at during the cipher.init(...). @see initializeKey function that configures a key and invokes
     * the cipher.init() function
     * Different engines use differing flavors of keys.
     *
     * Example of the DSL-type syntax:
     *  val key = initializeKey(cipher) {
     *      keyFromString("Test1234")
     *      forEncryption = false
     *  }
     *
     *  This example constructs a KeyParameter, with the String decoded into bytes using the default
     *  US-ASCII charset. It also overrides the default forEncyption flag, indicating key is used for
     *  decryption not encryption.
     *
     *  See the builders various properties and functions for details on how keys can be configured.
     */
    class KeyConfiguration() {
        /**
         * An array of bytes which is the key used. Note that if a Digest is also configured and
         * a hashKeyLength is set, this value will be changed to the hash value at build time. See
         * vars [stringKey] and [stringKeyCharset] for setting [key] from a String.
         */
        var key = UByteArray(0)

        /**
         * Engine sets this to its block size, which is required IV size if [ivSizeMatchBlock] is true
         */
        var ivSize = 0u

        /**
         * When using [stringKey], use this charset to encode the string into bytes for the true key.
         * This must be set before setting [stringKey]
         */
        var stringKeyCharset = Charset(Charsets.Utf8)
        /**
         * Setting this also sets [key] to the encoded value of this string using [stringKeyCharset].
         */
        var stringKey = ""
            set(value) {
                field = value
                key = stringKeyCharset.encode(value).toUByteArray()
            }

        /**
         * In most cases if an Initialization Vector is used, it should be the same size as the block
         * size of the engine used. Set this to false to allow other sizes to be used.
         */
        var ivSizeMatchBlock = true

        /**
         * Maximum byte count for content of an IV. This is used as a reasonableness check. Override
         * if required, before using setting the IV either manually or by reading it from a file.
         */
        var ivSizeLimit = 32

        /**
         * Set this to a UByteArray containing the Initialization Vector desired for the cipher.
         */
        var iv = UByteArray(0)
            set(value) {
                if (value.size > ivSizeLimit)
                    throw IllegalArgumentException("IV must not be larger than $ivSizeLimit. Typical value for this engine is ${ivSize}. Size rejected: ${value.size}")
                if (ivSizeMatchBlock && value.isNotEmpty() && value.size != ivSize.toInt())
                    throw IllegalArgumentException("If specified, IV size: ${value.size} must be same as block size: $ivSize")
                field = value
            }

        /**
         * Set this to a Digest algorithm if the cipher requires fixed length keys.  [hashKeyLength] must
         * also be set.  At build time the selected hash algorithm will be applied to the [key] value.
         * [key] will be changed to a new UByteArray of [hashKeyLength] length, containing the hash result.
         * Default is no Digest, leaving the bytes in [key] unchanged.
         */
        var keyDigest: Digests = Digests.None

        /**
         * Use in conjunction with the keyDigest configured. Specified in Bytes. Normally let this be
         * set by the build function after choosing a keyDigest value.
         */
        var hashKeyLength = 0
            set(value) {
                field = value
                if (value < 16 || value > 512) throw IllegalArgumentException("Key length in bytes ($value) must be between 16 and 512")
            }

        var hashKeyLengthBits = hashKeyLength * 8
            get() = hashKeyLength * 8
            set(value) {
                field = value
                if (value % 8 > 0) throw IllegalArgumentException("Key length in bits must be a multiple of 8")
                hashKeyLength = value / 8
            }

        /**
         * Assign a configured instance of a SecureRandom source to be used for cryptographically strong
         * random number generation. Default is none.
         */
        var secureRandom: SecureRandom? = null

        /**
         * Used by AEAD schemes like CCM and GCM. macSize must be must be 4, 6, 8, 10, 12, 14, or 16 bytes.
         * Use [authenticatedEncryptionAssociatedData] to set this value
         */
        private var macSizeBytes = 0
            set(value) {
                if (value < 4 || value > 16 || (value % 2) > 0)
                    throw IllegalArgumentException("macSize in bytes must be between 4 and 16, divisible by 2")
                field = value
            }
        /**
         * Used by AEAD schemes like CCM and GCM. size must be beteen 7 and 13 bytes.
         * Use [authenticatedEncryptionAssociatedData] to set this value
         */
        private var nonce = UByteArray(0)
            set(value) {
                if (value.size < 7 || value.size > 13)
                    throw IllegalArgumentException("nonce length must be between 7 and 13 bytes: ${value.size}")
                field = value
            }

        /**
         * Used by AEAD schemes like CCM and GCM.
         * Use [authenticatedEncryptionAssociatedData] to set this value
         */
        private var associatedText = UByteArray(0)

        /**
         * Set the required attributes for encryption using AEAD (Authenticated Encryption with
         * Associated Data). Currently only GCM and CCM chaining modes support use of this.
         *
         * @param macSizeBytes must be 4, 6, 8, 10, 12, 14, or 16 bytes.
         * @param nonce must be between 7 and 13 bytes
         * @param associatedText defaults to none.
         *
         * @see <a href="https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)">Wikipedia on Authenticated Encryption</a>
         */
        fun authenticatedEncryptionAssociatedData(
            macSizeBytes: Int,
            nonce: UByteArray,
            associatedText: UByteArray = UByteArray(0)
        ) {
            this.macSizeBytes = macSizeBytes
            this.nonce = nonce
            this.associatedText = associatedText
        }

        fun build(cipher: Cipher): CipherParameters {
            val engine = cipher.engine
            var tempKey = key
            val tempDigest = keyDigest
            if (tempDigest != Digests.None) {
                val digestImpl = when (tempDigest) {
                    Digests.SHA1 -> SHA1Digest()
                    Digests.SHA256 -> SHA256Digest()
                    Digests.SHA384 -> SHA384Digest()
                    Digests.SHA512 -> SHA512Digest()
                    Digests.MD5 -> MD5Digest()
                    Digests.MD4 -> MD4Digest()
                    Digests.MD2 -> MD2Digest()
                    Digests.RIPEMD128 -> RIPEMD128Digest()
                    Digests.RIPEMD160 -> RIPEMD160Digest()
                    Digests.Whirlpool -> WhirlpoolDigest()
                    else -> throw IllegalStateException("should never happen :-)")
                }
                if (hashKeyLength == 0) {
                    hashKeyLength = if (tempDigest == Digests.MD5 && engine is DESedeEngine)
                        engine.keySize
                    else
                        digestImpl.digestSize
                }
                tempKey = digestImpl.hash(key, resultLen = hashKeyLength)
            }
            val keyParm = KeyParameter(tempKey)
            val parm = if (macSizeBytes > 0) {
                if (cipher.mode != CipherModes.CCM && cipher.mode != CipherModes.GCM)
                    throw IllegalArgumentException("AEAD parameters only usable with CCM or GCM modes")
                AEADParameters(keyParm, macSizeBytes * 8, nonce, associatedText)
            } else
                secureRandom?.let { ParametersWithRandom(keyParm, it) }
                    ?: if (iv.isNotEmpty())
                        ParametersWithIV(keyParm, iv)
                    else
                        keyParm
            return parm
        }
    }
}