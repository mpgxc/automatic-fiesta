plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// A versão vive em VERSION, na raiz do repositório, e nada mais a declara.
//
// Antes existiam duas cópias — o versionName aqui e o CFBundleShortVersionString
// do Info.plist da UI — e elas já tinham divergido, 0.1.1 contra 0.1.0, sem
// ninguém notar. Duas cópias de um mesmo fato não permanecem iguais por boa
// vontade; permanecem iguais quando só existe uma.
val versao = rootProject.file("../../VERSION").readText().trim()

// Derivado, não digitado. O Android compara o versionCode para decidir se um
// APK é atualização, e esquecer de subi-lo produz um pacote que se recusa a
// instalar sobre o anterior sem dizer por quê — foi o que quase aconteceu no
// bump anterior, lembrado por acaso. 0.1.1 vira 101; 1.2.3 vira 10203.
val versaoCodigo = versao.split(".").let { partes ->
    require(partes.size == 3) { "VERSION precisa ser MAJOR.MINOR.PATCH; veio '$versao'" }
    partes[0].toInt() * 10000 + partes[1].toInt() * 100 + partes[2].toInt()
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
        versionCode = versaoCodigo
        versionName = versao
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // A keystore vem do ambiente, nunca do repositório. Quando as variáveis não
    // estão presentes — build local, fork, PR de terceiro — o bloco não é
    // criado e o release sai *sem assinatura*, que é o comportamento honesto:
    // melhor um APK que se recusa a instalar do que um assinado por uma chave
    // descartável, porque a assinatura é a identidade do app e trocá-la impede
    // qualquer atualização futura sobre a instalação existente.
    //
    // `takeIf { isNotBlank() }` não é decoração: o GitHub Actions define a
    // variável como string VAZIA quando a expressão que a alimenta não resolve
    // em nada, e getenv devolve "" — não null. Sem isto, o caminho "sem
    // keystore" entraria no ramo de assinatura e morreria em `file("")`.
    val keystorePath: String? = System.getenv("ANDROID_KEYSTORE_PATH")?.takeIf { it.isNotBlank() }

    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
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

    // O tema do AndroidManifest é Theme.Material3.*, que é um recurso XML do
    // Material Components — o BOM do Compose entrega o código de material3, não
    // os temas. Sem esta linha o AAPT falha em processDebugResources.
    implementation("com.google.android.material:material:1.12.0")

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

    // O `org.json` do android.jar é só assinatura: em teste unitário todo
    // método lança "not mocked". Esta é a implementação de verdade, a mesma
    // que o AOSP empacota, e no classpath de teste ela vem antes do stub.
    // Sem ela não dá para exercitar nada que leia quadro do protocolo.
    testImplementation("org.json:json:20240303")
}
