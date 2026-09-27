import org.gradle.internal.os.OperatingSystem

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
}

// iOS targets can only be compiled on macOS, where Xcode and the Apple
// platform libraries are available. Declare them only there so that Linux
// hosts can still build and test the JVM target without a missing-toolchain
// failure during configuration.
val hostIsMac = OperatingSystem.current().isMacOsX

kotlin {
    jvm()

    if (hostIsMac) {
        val iosTargets = listOf(iosX64(), iosArm64(), iosSimulatorArm64())
        iosTargets.forEach { target ->
            target.binaries.framework {
                baseName = "Shared"
                isStatic = true
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.serialization.json)
            implementation(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        jvmTest.dependencies {
            implementation(libs.junit)
        }
    }
}
