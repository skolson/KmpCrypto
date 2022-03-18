package com.oldguy.crypto

@Suppress("UNUSED_PARAMETER")
enum class SecureRandomCtr_DRBGCipher(cipherName: String) {
    AES128("AES-128"), AES_192("AES-192"), AES256("AES-256")
}

@Suppress("UNUSED_PARAMETER")
enum class SecureRandomCtr_DRBGStrength(value: Int) {
    Strength112(112), Strength128(128), Strength192(192), Strength256(256)
}