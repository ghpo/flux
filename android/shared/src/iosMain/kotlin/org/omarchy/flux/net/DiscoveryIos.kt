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
    private val scope = CoroutineScope(SupervisorJob() + blockingDispatcher)

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
