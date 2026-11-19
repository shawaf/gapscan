android {
    defaultConfig {
        // ruleid: gapscan.kotlin.gradle-min-sdk-outdated
        minSdk = 19
        // ok: gapscan.kotlin.gradle-min-sdk-outdated
        targetSdk = 19
    }
    buildTypes {
        // ruleid: gapscan.kotlin.gradle-release-debuggable
        getByName("release") {
            isDebuggable = true
        }
        // ok: gapscan.kotlin.gradle-release-debuggable
        getByName("debug") {
            isDebuggable = true
        }
        // ruleid: gapscan.kotlin.gradle-release-not-minified
        release {
            isMinifyEnabled = false
        }
        // ok: gapscan.kotlin.gradle-release-not-minified
        named("release") {
            isMinifyEnabled = true
        }
    }
}

android {
    defaultConfig {
        // ok: gapscan.kotlin.gradle-min-sdk-outdated
        minSdk = 26
    }
}
