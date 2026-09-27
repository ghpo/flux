package org.omarchy.flux.core

import java.io.File

actual fun readTextFile(path: String): String? =
    File(path).takeIf { it.exists() }?.readText()

actual fun writeTextFile(path: String, text: String) {
    File(path).writeText(text)
}
