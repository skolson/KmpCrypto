import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

buildscript {
    val kotlinVersion: String by extra("1.9.10")
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
        classpath("com.android.tools.build:gradle:8.3.0-alpha03")
        // The following line works around an atomicfu gradle plugin issue (github atomicfu issue 248)
        classpath("org.jetbrains.kotlin:atomicfu:$kotlinVersion")
        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.22.0")
    }
}

allprojects {
    tasks.withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "11"
        }
    }
}
