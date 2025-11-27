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
    
    buildFeatures {
        dataBinding = true
    }
    
    packaging {
        resources {
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.10.0")
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.76")
}
