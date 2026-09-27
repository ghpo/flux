@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.net

import kotlinx.cinterop.IntVar
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.posix.AF_INET
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_REUSEADDR
import platform.posix.accept
import platform.posix.bind
import platform.posix.close
import platform.posix.connect
import platform.posix.errno
import platform.posix.listen
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.sockaddr_in
import platform.posix.socket

internal class PosixStream(internal val fd: Int) : Stream {
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        val n = buffer.usePinned { pinned ->
            recv(fd, pinned.addressOf(offset), length.toULong(), 0)
        }
        return n.toInt()
    }

    override fun write(bytes: ByteArray) {
        var sent = 0
        while (sent < bytes.size) {
            val n = bytes.usePinned { pinned ->
                send(fd, pinned.addressOf(sent), (bytes.size - sent).toULong(), 0)
            }
            if (n <= 0) error("send failed (errno=$errno)")
            sent += n.toInt()
        }
    }

    override fun close() {
        close(fd)
    }
}

private class PosixTcpServer(private val fd: Int, private val port: Int) : TcpServer {
    override fun localPort(): Int = port

    override fun accept(): Stream? {
        val clientFd = memScoped {
            val addr = alloc<sockaddr_in>()
            val len = alloc<UIntVar>().apply { value = sizeOf<sockaddr_in>().toUInt() }
            accept(fd, addr.ptr.reinterpret(), len.ptr)
        }
        if (clientFd < 0) return null
        return PosixStream(clientFd)
    }

    override fun close() {
        close(fd)
    }
}

actual fun openTcpServer(portRange: IntRange): TcpServer? {
    for (port in portRange) {
        val fd = socket(AF_INET, SOCK_STREAM, 0)
        if (fd < 0) continue
        val bound = memScoped {
            val on = alloc<IntVar>().apply { value = 1 }
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, on.ptr, sizeOf<IntVar>().toUInt())
            val addr = alloc<sockaddr_in>()
            addr.sin_family = AF_INET.convert()
            addr.sin_port = htons(port.toUShort())
            addr.sin_addr.s_addr = 0u
            if (bind(fd, addr.ptr.reinterpret(), sizeOf<sockaddr_in>().toUInt()) < 0) return@memScoped false
            if (listen(fd, 16) < 0) return@memScoped false
            true
        }
        if (!bound) {
            close(fd)
            continue
        }
        return PosixTcpServer(fd, port)
    }
    return null
}

actual fun tcpConnect(address: String, port: Int): Stream {
    val fd = socket(AF_INET, SOCK_STREAM, 0)
    if (fd < 0) error("socket failed (errno=$errno)")
    memScoped {
        val addr = alloc<sockaddr_in>()
        addr.sin_family = AF_INET.convert()
        addr.sin_port = htons(port.toUShort())
        addr.sin_addr.s_addr = parseIpv4(address) ?: 0u
        if (connect(fd, addr.ptr.reinterpret(), sizeOf<sockaddr_in>().toUInt()) < 0) {
            close(fd)
            error("connect to $address:$port failed (errno=$errno)")
        }
    }
    return PosixStream(fd)
}
