plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.notes"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.notes"
        minSdk = 26
        buildConfigField("String", "API_BASE", "\"https://api.example.com\"")
    }

    flavorDimensions += "env"
    productFlavors {
        create("dev") {
            dimension = "env"
            applicationIdSuffix = ".dev"
            buildConfigField("Boolean", "ENCRYPT_DB", "false")
        }
        create("prod") {
            dimension = "env"
            buildConfigField("Boolean", "ENCRYPT_DB", "true")
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
        }
        getByName("debug") {
            isDebuggable = true
        }
    }
}
