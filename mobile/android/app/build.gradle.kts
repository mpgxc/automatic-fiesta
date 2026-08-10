plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.phoneauth"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.phoneauth"
        // API 29: setUserAuthenticationParameters chegou na 30, e há um
        // fallback para o método depreciado abaixo disso. StrongBox exige 28+.
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.fragment:fragment-ktx:1.8.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.activity:activity-compose:1.9.2")

    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")

    // O que torna a assinatura biométrica possível: BiometricPrompt com
    // CryptoObject, para o Keystore só destravar a chave após a autenticação.
    implementation("androidx.biometric:biometric:1.1.0")

    // Leitura de QR no pareamento.
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")

    // SignedPayloadTest é um teste JVM puro, de propósito: os vetores
    // cross-plataforma precisam rodar sem emulador nem Robolectric, para que
    // uma divergência de bytes apareça no CI mais barato possível.
    testImplementation("junit:junit:4.13.2")
}
