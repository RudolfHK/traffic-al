import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

group = "io.github.rudolfhk.traffical"
version = "0.1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// Command-line tools for development; not part of the library the app uses.
val tools: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}
configurations[tools.implementationConfigurationName].extendsFrom(configurations.implementation.get())

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("captureReport") {
    description = "Converts native capture batches to PCAPNG + flows JSON (see tools/host-test)."
    classpath = tools.runtimeClasspath
    mainClass.set("io.github.rudolfhk.traffical.core.tools.CaptureReportKt")
}
