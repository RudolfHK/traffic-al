pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "traffic-al"

// :core is a standalone pure-Kotlin build (packet parsing, DNS, PCAPNG) so it can be
// built and unit-tested without the Android SDK: ./gradlew -p core test
includeBuild("core")
include(":app")
