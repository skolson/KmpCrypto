plugins {
    libs.plugins.also {
        alias(it.kotlin.multiplatform) apply false
        alias(it.android.library) apply false
        alias(it.kotlinx.atomicfu) apply false
    }
}