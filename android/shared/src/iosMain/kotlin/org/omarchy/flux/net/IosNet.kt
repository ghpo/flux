@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.net

internal fun htons(value: UShort): UShort {
    val v = value.toInt() and 0xFFFF
    return (((v and 0xFF) shl 8) or ((v shr 8) and 0xFF)).toUShort()
}

internal fun htonl(value: UInt): UInt =
    ((value and 0xFFu) shl 24) or
        ((value and 0xFF00u) shl 8) or
        ((value and 0xFF0000u) shr 8) or
        ((value and 0xFF000000u) shr 24)

internal fun ntohl(value: UInt): UInt = htonl(value)

internal fun parseIpv4(s: String): UInt? {
    val parts = s.split(".")
    if (parts.size != 4) return null
    var host = 0u
    for (p in parts) {
        val n = p.toIntOrNull() ?: return null
        if (n < 0 || n > 255) return null
        host = (host shl 8) or n.toUInt()
    }
    return htonl(host)
}

internal fun formatIpv4(netOrder: UInt): String {
    val host = ntohl(netOrder)
    val a = (host shr 24) and 0xFFu
    val b = (host shr 16) and 0xFFu
    val c = (host shr 8) and 0xFFu
    val d = host and 0xFFu
    return "$a.$b.$c.$d"
}
