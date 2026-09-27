@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.core

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.UByteVar
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.fseek
import platform.posix.ftell
import platform.posix.fwrite
import platform.posix.SEEK_END
import platform.posix.SEEK_SET

actual fun readTextFile(path: String): String? {
    val file = fopen(path, "rb") ?: return null
    try {
        if (fseek(file, 0L, SEEK_END) != 0) return null
        val size = ftell(file)
        if (size < 0L) return null
        if (fseek(file, 0L, SEEK_SET) != 0) return null
        val buffer = ByteArray(size.toInt())
        buffer.usePinned { pinned ->
            fread(pinned.addressOf(0).reinterpret<UByteVar>(), 1uL, size.toULong(), file)
        }
        return buffer.decodeToString()
    } finally {
        fclose(file)
    }
}

actual fun writeTextFile(path: String, text: String) {
    val data = text.encodeToByteArray()
    val file = fopen(path, "wb") ?: return
    try {
        data.usePinned { pinned ->
            fwrite(pinned.addressOf(0).reinterpret<UByteVar>(), 1uL, data.size.toULong(), file)
        }
    } finally {
        fclose(file)
    }
}
