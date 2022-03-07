package com.oldguy.crypto

import com.oldguy.common.io.Charset
import com.oldguy.common.io.Charsets
import com.oldguy.common.io.UByteBuffer

class CipherV2 {
    lateinit var keyConfiguration: KeyConfiguration
    lateinit var parameters: CipherParameters

    lateinit var engineParm: BlockCipher

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
        engineParm = when (tokens[0]) {
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
        engineParm = Engine().arg()
    }

    inline fun key(arg: KeyConfiguration.() -> Unit) {
        keyConfiguration = KeyConfiguration().apply { arg() }.apply {
            parameters = build()
        }
    }

    fun build(): CipherV2 {
        engineParm.apply {
            val modeEngine = when (mode) {
                CipherModes.None -> this
                CipherModes.CBC -> CBCBlockCipher(this)
                CipherModes.CFB -> CFBBlockCipher(this, cfbBitSize)
                CipherModes.CCM -> CCMBlockCipher(this)
                CipherModes.GCM -> GCMBlockCipher(this)
                CipherModes.ECB -> ECBBlockCipher(this)
            }
            engineParm = when (padding) {
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
     * @param output lambda is invoked once for each output block.  If
     */
    suspend fun process(
        encrypt: Boolean,
        input: suspend () -> UByteBuffer,
        output: suspend (buffer: UByteBuffer) -> Unit
    ) {
        engineParm.init(encrypt, parameters)
        val blockSize = engineParm.blockSize
        var buf = input()
        while (buf.hasRemaining) {
            val blockIn = UByteArray(blockSize)
            val blockOut = UByteArray(blockSize)
            val outBuf = UByteBuffer(1024)
            var totalLength = 0
            while (buf.hasRemaining) {
                if (buf.remaining < blockSize)
                    blockIn.fill(0u)
                buf.getBytes(blockIn)
                val length = engineParm.processBlock(blockIn, 0, blockOut, 0)
                if (length > outBuf.remaining)
                    throw IllegalStateException("buf capacity exceeded")
                outBuf.putBytes(blockOut)
                totalLength += length
            }
            outBuf.rewind()
            output(outBuf.slice(totalLength))
            buf = input()
        }
    }

    companion object {
        fun make(lambda: CipherV2.() -> Unit): CipherV2 {
            return CipherV2()
                .apply(lambda)
                .build()
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
    class KeyConfiguration {
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