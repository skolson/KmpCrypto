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

 * A DSL-like syntax offers flexibility for setting up a cipher and its key.
 * CipherV2.build {
 *     engine { aes() }
 *     mode = CipherModes.CBC
 *     padding = Paddings.PKCS7
 *     key {
 *         stringKeyCharset = Charset(Charsets.Utf16le)
 *         stringKey = "SomeKey"
 *         hashKeyLengthBits = 256
 *         keyDigest = Digests.SHA256
 *     }
 * }
 * configures a cipher with AES, CBC chaining, and PKCS7 padding. It also sets the key to a string
 * value encoded with UTF-16 Little Endian encoding.
 */
class Cipher {
    lateinit var keyConfiguration: KeyConfiguration
    lateinit var parameters: CipherParameters

    lateinit var engine: BlockCipher

    var bufferSize = 4096u

    /**
     * Any of the algorithm modes in [CipherModes] can be used with any engine. Default is none.
     */
    var mode = CipherModes.None

    /**
     * this parm is specific to CFB chaining mode and is ignored otherwise.  it defaults to 128
     * as the most commonly used value, or can be smaller in multiples of 8.
     */
    var cfbBitSize = 128

    /**
     * Any of the valid padding modes can be applied to any engine and chaining.  Default is none.
     */
    var padding = Paddings.None

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
     * These functions supply the available engine
     */
    class Engine {
        fun aes(): BlockCipher {
            return AESEngine()
        }

        fun rc2(): BlockCipher {
            return RC2Engine()
        }

        fun rc4(): BlockCipher {
            return BlockCipherAdapter(RC4Engine())
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

    inline fun engine(arg: Engine.() -> BlockCipher) {
        engine = Engine().arg()
        build()
    }

    inline fun key(arg: KeyConfiguration.() -> Unit) {
        keyConfiguration = KeyConfiguration(engine.ivSize)
            .apply { arg() }
            .apply {
                parameters = build()
            }
    }

    fun build(): Cipher {
        engine.apply {
            val modeEngine = when (mode) {
                CipherModes.None -> this
                CipherModes.CBC -> CBCBlockCipher(this)
                CipherModes.CFB -> CFBBlockCipher(this, cfbBitSize)
                CipherModes.CCM -> CCMBlockCipher(this)
                CipherModes.GCM -> GCMBlockCipher(this)
                CipherModes.ECB -> ECBBlockCipher(this)
            }
            engine = when (padding) {
                Paddings.None -> modeEngine
                Paddings.PKCS7 -> PaddedBufferedBlockCipher(modeEngine)
            }
        }
        return this
    }

    /**
     * Initializes the configured Cipher, then repeatedly calls the input function to get input data.
     * Process ends when input is called with an empty (!hasRemaining) buffer.  Output is called
     * once for each processed block, with a buffer positined at zero and remaining = bytes produced.
     * @param encrypt true if input data is being encrypted. False if input data is being decrypted.
     * @param input lambda should provide buffers until all input data is processed. Note that every
     * block cipher has a block size, and that the incoming buffers should be a non zero multiple of
     * that block size in length until the last bloc, which can be any size.
     * @param output buffer is of [bufferSize] size. lambda is invoked once each time the buffer is
     * full (or close to it). Buffer is flipped before [output] is called, so the buffer's remaining
     * value is always the number of bytes to retrieve.
     */
    suspend fun process(
        encrypt: Boolean,
        input: suspend () -> ByteBuffer,
        output: suspend (buffer: ByteBuffer) -> Unit
    ): ULong {
        engine.init(encrypt, parameters)
        val blockSize = engine.blockSize
        val reader = BufferReader( input )
        val blockIn = ByteArray(blockSize)
        val outBuf = ByteBuffer(bufferSize.toInt())
        var readCount = reader.read(blockIn, 0, blockSize)
        var totalRead = readCount.toULong()
        while (readCount > 0) {
            val blockOut = UByteArray(blockSize)
            if (readCount < blockSize)
                blockIn.fill(0)
            val length = engine.processBlock(blockIn.toUByteArray(), 0, blockOut, 0)
            if (length > outBuf.remaining)
                throw IllegalStateException("buf capacity exceeded")
            outBuf.putBytes(blockOut.toByteArray())
            if (outBuf.remaining < blockSize) {
                output(outBuf.flip())
                outBuf.clear()
            }
            readCount = reader.read(blockIn, 0, blockSize)
            totalRead += readCount.toULong()
        }
        if (outBuf.position > 0)
            output(outBuf.flip())
        return totalRead
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
        val buf = ByteBuffer(bufferSize.toInt())
        try {
            if (encrypt && keyConfiguration.iv.isNotEmpty()) {
                outFile.write(UByteBuffer(keyConfiguration.iv))
            }
            return process(encrypt,
                input = {
                    inFile.read(buf)
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
    class KeyConfiguration(val ivSize: Int) {
        /**
         * An array of bytes which is the key used. Note that if a Digest is also configured and
         * a hashKeyLength is set, this value will be changed to the hash value at build time. See
         * vars [stringKey] and [stringKeyCharset] for setting [key] from a String.
         */
        var key = UByteArray(0)

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
         * Set this to a UByteArray containing the Initialization Vector desired for the cipher.
         */
        var iv = UByteArray(0)
            set(value) {
                if (value.isNotEmpty() && value.size != ivSize)
                    throw IllegalArgumentException("If specified, IV size must be same as block size: $ivSize")
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
         * Use in conjunction with the keyDigest configured. Specified in Bytes
         */
        var hashKeyLength = 0
            set(value) {
                field = value
                if (value <= 16 || value > 512) throw IllegalArgumentException("Key length in bytes must be between 16 and 512")
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

        var macSize = 0
        private var nonce = UByteArray(0)
        private var associatedText = UByteArray(0)

        /**
         * Set the required attributes for encryption using AEAD (Authenticated Encryption with
         * Associated Data). Currently only GCM and CCM chaining modes support use of this.
         *
         * @param macSize must be between 32 and 128, in multiples of 8.
         * @param nonce
         * @param associatedText defaults to none.
         *
         * @see <a href="https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)">Wikipedia on Authenticated Encryption</a>
         */
        fun authenticatedEncryptionAssociatedData(
            macSize: Int,
            nonce: UByteArray,
            associatedText: UByteArray = UByteArray(0)
        ) {
            this.macSize = macSize
            this.nonce = nonce
            this.associatedText = associatedText
        }

        fun build(): CipherParameters {
            var tempKey = key
            val tempDigest = keyDigest
            if (hashKeyLength > 0) {
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
                    tempKey = digestImpl.hash(key, resultLen = hashKeyLength)
                }
            }
            val keyParm = KeyParameter(tempKey)
            val parm = if (macSize > 0)
                AEADParameters(keyParm, macSize, iv, associatedText)
            else
                secureRandom?.let { ParametersWithRandom(keyParm, it) }
                    ?: if (iv.isNotEmpty())
                        ParametersWithIV(keyParm, iv)
                    else
                        keyParm
            return parm
        }
    }
}