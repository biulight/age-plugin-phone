plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.biulight.phone_identity"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    sourceSets {
        getByName("test").resources.srcDir(file("../../../docs/test-vectors"))
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.camera:camera-camera2:1.5.3")
    implementation("androidx.camera:camera-mlkit-vision:1.5.3")
    implementation("androidx.camera:camera-view:1.5.3")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.2")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.19.2")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation(project(":tauri-android"))
    testImplementation("junit:junit:4.13.2")
}
