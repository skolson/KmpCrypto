package com.oldguy.crypto

class ECBBlockCipher(val cipher: BlockCipher) : BlockCipher {
    override val algorithmName = cipher.algorithmName
    override val blockSize = cipher.blockSize
    override val ivSize = blockSize

    override fun init(forEncryption: Boolean, params: CipherParameters) {
        if (params is ParametersWithIV) {
            cipher.init(forEncryption, params.parameters)
        } else if (params is KeyParameter) {
            cipher.init(forEncryption, params)
        } else {
            throw IllegalArgumentException("invalid parameters passed to ECB")
        }
    }

    override fun processBlock(
        inBlock: UByteArray,
        inOff: Int,
        outBlock: UByteArray,
        outOff: Int
    ): Int {
        return cipher.processBlock(inBlock, inOff, outBlock, outOff)
    }

    override fun reset() {
        cipher.reset()
    }
}
