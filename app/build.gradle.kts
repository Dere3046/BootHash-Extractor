plugins {
    id("com.android.application")
}

android {
    namespace = "com.dere.keyattestation"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.dere.keyattestation"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
    
    // 启用 DataBinding
    buildFeatures {
        dataBinding = true
    }
    
    // 必须配置 packagingOptions 以避免 Bouncy Castle 的一些冲突
    packaging {
        resources {
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.10.0")
    
    // 核心依赖：Bouncy Castle 用于 ASN.1 解析
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.76")
}