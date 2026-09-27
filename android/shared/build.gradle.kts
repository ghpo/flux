import org.gradle.internal.os.OperatingSystem

plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

// iOS targets can only be compiled on macOS, where Xcode and the Apple
// platform libraries are available. Declare them only there so that Linux
// hosts can still build and test the JVM target without a missing-toolchain
// failure during configuration.
val hostIsMac = OperatingSystem.current().isMacOsX

kotlin {
    jvm()

    if (hostIsMac) {
        iosX64()
        iosArm64()
        iosSimulatorArm64()
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.serialization.json)
        }
        jvmMain.dependencies {
            implementation(libs.bouncycastle)
            implementation(libs.bouncycastle.pkix)
        }
        jvmTest.dependencies {
            implementation(libs.junit)
        }
    }
}
