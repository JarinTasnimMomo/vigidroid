import com.android.build.api.dsl.AaptOptions

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.msh.vigidroid"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.msh.vigidroid"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    // Real org.json for JVM unit tests (android.jar stubs throw "not mocked").
    testImplementation("org.json:json:20240303")
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
    implementation(libs.onnxruntime.android)
    implementation(libs.gson)
}