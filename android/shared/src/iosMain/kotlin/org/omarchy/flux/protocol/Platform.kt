package org.omarchy.flux.protocol

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.Foundation.NSDate

@OptIn(ExperimentalForeignApi::class)
actual fun sha256(data: ByteArray): ByteArray = memScoped {
    val out = allocArray<ByteVar>(CC_SHA256_DIGEST_LENGTH)
    data.usePinned { pinned ->
        CC_SHA256(pinned.addressOf(0), data.size.convert(), out.reinterpret())
    }
    out.readBytes(CC_SHA256_DIGEST_LENGTH)
}

@OptIn(ExperimentalForeignApi::class)
actual fun currentTimeMillis(): Long = (NSDate().timeIntervalSince1970 * 1000.0).toLong()
