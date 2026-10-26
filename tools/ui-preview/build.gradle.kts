// Renders the app's shared Compose screens to PNG files without Android: compiles
// core/, the UI models and app/.../ui/common with Compose for Desktop and draws them
// headlessly. Compose Desktop 1.5.12 is the newest version that needs nothing from
// Google's Maven repository; the shared code sticks to APIs it has in common with the
// app's Compose version.
//
//   ./gradlew -p tools/ui-preview render   -> tools/ui-preview/build/screens/*.png
plugins {
    kotlin("jvm") version "1.9.22"
    id("org.jetbrains.compose") version "1.5.12"
}

val repo: File = rootDir.resolve("../..").canonicalFile
val app = repo.resolve("app/src/main/java/io/github/rudolfhk/traffical")

kotlin.sourceSets["main"].kotlin.srcDirs(
    repo.resolve("core/src/main/kotlin"),
    app.resolve("model"),
    app.resolve("ui/common"),
)

dependencies {
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation("org.jetbrains.compose.material:material-icons-core:1.5.12")
    implementation(kotlin("reflect"))
}

tasks.register<JavaExec>("render") {
    description = "Renders the shared screens with sample data to build/screens."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.github.rudolfhk.traffical.preview.PreviewKt")
    args(
        layout.buildDirectory.dir("screens").get().asFile.path,
        repo.resolve("app/src/main/res/values/strings.xml").path,
        repo.resolve("app/src/main/assets/enrichment").path,
    )
}
