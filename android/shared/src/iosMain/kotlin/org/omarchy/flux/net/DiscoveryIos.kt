@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.net

import kotlinx.cinterop.IntVar
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile
import platform.posix.AF_INET
import platform.posix.SOCK_DGRAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_BROADCAST
import platform.posix.SO_REUSEADDR
import platform.posix.bind
import platform.posix.close
import platform.posix.recvfrom
import platform.posix.sendto
import platform.posix.setsockopt
import platform.posix.sockaddr_in
import platform.posix.socket

private class IosLanDiscovery(private val listener: DiscoveryListener, private val port: Int) : LanDiscovery {
    private var fd: Int = -1
    @Volatile private var running = false
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun start(identityLine: () -> String) {
        if (running) return
        running = true
        val sock = socket(AF_INET, SOCK_DGRAM, 0)
        if (sock < 0) {
            running = false
            return
        }
        fd = sock
        memScoped {
            val on = alloc<IntVar>().apply { value = 1 }
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, on.ptr, sizeOf<IntVar>().toUInt())
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, on.ptr, sizeOf<IntVar>().toUInt())
        }
        memScoped {
            val addr = alloc<sockaddr_in>()
            addr.sin_family = AF_INET.convert()
            addr.sin_port = htons(port.toUShort())
            addr.sin_addr.s_addr = 0u
            if (bind(fd, addr.ptr.reinterpret(), sizeOf<sockaddr_in>().toUInt()) < 0) {
                close(fd)
                fd = -1
                running = false
                return
            }
        }
        scope.launch { receiveLoop() }
        broadcast(identityLine())
    }

    override fun announce(line: String, address: String) {
        val target = parseIpv4(address) ?: return
        sendTo(line, target)
    }

    override fun broadcast(line: String) {
        sendTo(line, 0xFFFFFFFFu)
    }

    override fun stop() {
        running = false
        if (fd >= 0) {
            close(fd)
            fd = -1
        }
    }

    private fun sendTo(line: String, addrValue: UInt) {
        if (!running || fd < 0) return
        val bytes = line.encodeToByteArray()
        memScoped {
            val dest = alloc<sockaddr_in>()
            dest.sin_family = AF_INET.convert()
            dest.sin_port = htons(port.toUShort())
            dest.sin_addr.s_addr = addrValue
            bytes.usePinned { pinned ->
                sendto(fd, pinned.addressOf(0), bytes.size.toULong(), 0, dest.ptr.reinterpret(), sizeOf<sockaddr_in>().toUInt())
            }
        }
    }

    private fun receiveLoop() {
        val buffer = ByteArray(64 * 1024)
        while (running) {
            val received = memScoped {
                val src = alloc<sockaddr_in>()
                val srcLen = alloc<UIntVar>().apply { value = sizeOf<sockaddr_in>().toUInt() }
                val n = buffer.usePinned { pinned ->
                    recvfrom(fd, pinned.addressOf(0), buffer.size.toULong(), 0, src.ptr.reinterpret(), srcLen.ptr)
                }
                if (n <= 0) return@memScoped null
                buffer.decodeToString(0, n.toInt()) to formatIpv4(src.sin_addr.s_addr)
            }
            if (received != null) {
                listener.onDatagram(received.first, received.second)
            }
        }
    }
}

actual fun lanDiscovery(listener: DiscoveryListener, port: Int): LanDiscovery = IosLanDiscovery(listener, port)

private fun htons(value: UShort): UShort {
    val v = value.toInt() and 0xFFFF
    return (((v and 0xFF) shl 8) or ((v shr 8) and 0xFF)).toUShort()
}

private fun htonl(value: UInt): UInt =
    ((value and 0xFFu) shl 24) or
        ((value and 0xFF00u) shl 8) or
        ((value and 0xFF0000u) shr 8) or
        ((value and 0xFF000000u) shr 24)

private fun ntohl(value: UInt): UInt = htonl(value)

private fun parseIpv4(s: String): UInt? {
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

private fun formatIpv4(netOrder: UInt): String {
    val host = ntohl(netOrder)
    val a = (host shr 24) and 0xFFu
    val b = (host shr 16) and 0xFFu
    val c = (host shr 8) and 0xFFu
    val d = host and 0xFFu
    return "$a.$b.$c.$d"
}
