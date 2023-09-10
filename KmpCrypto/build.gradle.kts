import org.gradle.kotlin.dsl.signing
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework
import org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType

plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("native.cocoapods")
    id("maven-publish")
    id("signing")
    id("kotlinx-atomicfu")
    id("org.jetbrains.dokka") version "1.9.0"
    id("com.github.ben-manes.versions") version "0.48.0"
}

val mavenArtifactId = "kmp-crypto"
val appleFrameworkName = "KmpCrypto"
group = "com.oldguy"
version = "0.1.4"

val androidMinSdk = 26
val androidTargetSdkVersion = 34
val iosMinSdk = "14"
val kmpPackageName = "com.oldguy.crypto"
val kotlinCoroutinesVersion = "1.7.3"
val kotlinCoroutines = "org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinCoroutinesVersion"
val kotlinCoroutinesTest = "org.jetbrains.kotlinx:kotlinx-coroutines-test:$kotlinCoroutinesVersion"

android {
    compileSdk = androidTargetSdkVersion
    buildToolsVersion = "34.0.0"
    namespace = "com.oldguy.crypto"

    defaultConfig {
        minSdk = androidMinSdk

        buildFeatures {
            buildConfig = false
        }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("tools/consumer-rules.pro")
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        targetCompatibility = JavaVersion.VERSION_11
    }

    packaging.resources.excludes.addAll( listOf(
        "META-INF/versions/9/*"
    ))

    dependencies {
        testImplementation("junit:junit:4.13.2")
        androidTestImplementation("androidx.test:core:1.5.0")
        androidTestImplementation("androidx.test:runner:1.5.2")
        androidTestImplementation("androidx.test.ext:junit:1.1.5")
    }
}

tasks {
    dokkaHtml {
        moduleName.set("Kotlin Multiplatform Cryptography Library")
        dokkaSourceSets {
            named("commonMain") {
                noAndroidSdkLink.set(false)
                includes.from("$appleFrameworkName.md")
            }
        }
    }
}

val junitVersion = "5.10.0"
val junit5 = "org.junit.jupiter:junit-jupiter-api:$junitVersion"
val junit5Runtime = "org.junit.jupiter:junit-jupiter-engine:$junitVersion"

kotlin {
    androidTarget {
        publishLibraryVariants("release", "debug")
        mavenPublication {
            artifactId = artifactId.replace(project.name, mavenArtifactId)
        }
    }

    val githubUri = "skolson/$appleFrameworkName"
    val githubUrl = "https://github.com/$githubUri"
    cocoapods {
        ios.deploymentTarget = iosMinSdk
        summary = "Kotlin Multiplatform Cryptography"
        homepage = githubUrl
        license = "Apache 2.0"
        authors = "Steven Olson"
        framework {
            baseName = appleFrameworkName
            isStatic = true
            embedBitcode(org.jetbrains.kotlin.gradle.plugin.mpp.BitcodeEmbeddingMode.BITCODE)
        }
        // Maps custom Xcode configuration to NativeBuildType
        xcodeConfigurationToNativeBuildType["CUSTOM_DEBUG"] = NativeBuildType.DEBUG
        xcodeConfigurationToNativeBuildType["CUSTOM_RELEASE"] = NativeBuildType.RELEASE
    }

    val appleXcf = XCFramework()
    macosX64 {
        binaries {
            framework {
                baseName = appleFrameworkName
                appleXcf.add(this)
                isStatic = true
            }
        }
    }
    iosX64 {
        binaries {
            framework {
                appleXcf.add(this)
                isStatic = true
                freeCompilerArgs = freeCompilerArgs + listOf("-Xoverride-konan-properties=osVersionMin=$iosMinSdk")
            }
        }
    }
    iosArm64 {
        binaries {
            framework {
                appleXcf.add(this)
                isStatic = true
                embedBitcode("bitcode")
                freeCompilerArgs = freeCompilerArgs + listOf("-Xoverride-konan-properties=osVersionMin=$iosMinSdk")
            }
        }
    }
    jvm()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(kotlinCoroutines)
                implementation("io.github.skolson:kmp-io:0.1.4")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlinCoroutinesTest)
            }
        }
        val androidMain by getting {
            dependsOn(commonMain)
        }

        val androidUnitTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("junit:junit:4.13.2")
            }
        }
        val androidInstrumentedTest by getting {
            dependsOn(commonTest)
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("junit:junit:4.13.2")
            }
        }
        val appleNativeMain by creating {
            dependsOn(commonMain)
            kotlin.srcDir("src/appleNativeMain/kotlin")
        }
        val appleNativeTest by creating {
            kotlin.srcDir("src/appleNativeTest/kotlin")
            dependsOn(commonTest)
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlinCoroutinesTest)
            }
        }
        val iosX64Main by getting {
            dependsOn(appleNativeMain)
        }
        val iosX64Test by getting {
            dependsOn(appleNativeTest)
        }
        val iosArm64Main by getting {
            dependsOn(appleNativeMain)
        }
        val macosX64Main by getting {
            dependsOn(appleNativeMain)
        }
        val macosX64Test by getting {
            dependsOn(appleNativeTest)
        }
        val jvmMain by getting {
            dependsOn(commonMain)
        }
        val jvmTest by getting {
            dependsOn(commonTest)
            dependencies {
                implementation(kotlinCoroutinesTest)
                implementation("org.bouncycastle:bcprov-jdk15on:1.70")
            }
        }
        all {
            languageSettings {
                optIn("kotlin.ExperimentalUnsignedTypes")
            }
        }
    }

    // workaround starting with Gradle 8 and kotlin 1.8.x, supposedly fixed in Kotlin 1.9.20 (KT-55751)
    val workaroundAttribute = Attribute.of("com.oldguy.crypto", String::class.java)
    afterEvaluate {
        configurations {
            named("debugFrameworkIosFat").configure {
                attributes.attribute(workaroundAttribute, "iosFat")
            }
            named("podDebugFrameworkIosFat").configure {
                attributes.attribute(workaroundAttribute, "podIosFat")
            }
            named("releaseFrameworkIosFat").configure {
                attributes.attribute(workaroundAttribute, "iosFat")
            }
            named("podReleaseFrameworkIosFat").configure {
                attributes.attribute(workaroundAttribute, "podIosFat")
            }
        }
    }

    publishing {
        publications.withType(MavenPublication::class) {
            artifactId = artifactId.replace(project.name, mavenArtifactId)

            // workaround for https://github.com/gradle/gradle/issues/26091
            val dokkaJar = tasks.register("${this.name}DokkaJar", Jar::class) {
                group = JavaBasePlugin.DOCUMENTATION_GROUP
                description = "Dokka builds javadoc jar"
                archiveClassifier.set("javadoc")
                from(tasks.named("dokkaHtml"))
                archiveBaseName.set("${archiveBaseName.get()}-${this.name}")
            }
            artifact(dokkaJar)

            pom {
                name.set("$appleFrameworkName Kotlin Multiplatform Common File I/O")
                description.set("Cryptography Library on supported 64 bit platforms; Android IOS, Windows, Linux, MacOS")
                url.set(githubUrl)
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("oldguy")
                        name.set("Steve Olson")
                        email.set("skolson5903@gmail.com")
                    }
                }
                scm {
                    url.set(githubUrl)
                    connection.set("scm:git:git://git@github.com:${githubUri}.git")
                    developerConnection.set("cm:git:ssh://git@github.com:${githubUri}.git")
                }
            }
        }
    }
}

tasks.withType<Test> {
    testLogging {
        events("PASSED", "FAILED", "SKIPPED")
        exceptionFormat = TestExceptionFormat.FULL
        showStandardStreams = true
        showStackTraces = true
    }
}

task("testClasses").doLast {
    println("testClasses task Iguana workaround for KMP libraries")
}

signing {
    isRequired = false
    sign(publishing.publications)
}