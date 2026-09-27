@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.net

import kotlinx.cinterop.Arena
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.LongVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.plus
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.kCFAllocatorDefault
import platform.Security.SSLCopyPeerTrust
import platform.Security.SSLCreateContext
import platform.Security.SSLConnectionType
import platform.Security.SSLConnectionRef
import platform.Security.SSLContextRef
import platform.Security.SSLHandshake
import platform.Security.SSLProtocolSide
import platform.Security.SSLRead
import platform.Security.SSLSetCertificate
import platform.Security.SSLSetClientSideAuthenticate
import platform.Security.SSLSetConnection
import platform.Security.SSLSetIOFuncs
import platform.Security.SSLSetSessionOption
import platform.Security.SSLWrite
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateRef
import platform.Security.SecIdentityCreate
import platform.Security.SecIdentityRef
import platform.Security.SecKeyCreateWithData
import platform.Security.SecTrustCopyCertificateChain
import platform.Security.SecTrustRefVar
import platform.Security.errSSLClientAuthCompleted
import platform.Security.errSSLClosedGraceful
import platform.Security.errSSLServerAuthCompleted
import platform.Security.errSSLWouldBlock
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSSLSessionOptionBreakOnClientAuth
import platform.Security.kSSLSessionOptionBreakOnServerAuth
import platform.Security.kSSLAuthenticate
import platform.Security.kSSLStreamType
import platform.Security.noErr
import platform.posix.EAGAIN
import platform.posix.EWOULDBLOCK
import platform.posix.errno
import platform.posix.recv
import platform.posix.send
import platform.posix.size_tVar

private const val IO_ERROR = -36

actual fun wrapTls(
    socket: Stream,
    server: Boolean,
    certificate: ByteArray,
    privateKey: ByteArray,
): ConnectedLink {
    val fd = (socket as PosixStream).fd
    val identity = createIdentity(certificate, privateKey) ?: error("cannot build identity")
    val arena = Arena()
    val ctx = SSLCreateContext(
        null,
        if (server) SSLProtocolSide.kSSLServerSide else SSLProtocolSide.kSSLClientSide,
        SSLConnectionType.kSSLStreamType,
    ) ?: error("cannot create SSL context")

    val fdVar = arena.alloc<LongVar>()
    fdVar.value = fd.toLong()
    SSLSetConnection(ctx, fdVar.ptr)
    SSLSetIOFuncs(ctx, staticCFunction(::sslReadCallback), staticCFunction(::sslWriteCallback))

    val certs = CFArrayCreate(kCFAllocatorDefault, arena.allocArray(1) { identity }.ptr.reinterpret(), 1, null)
    SSLSetCertificate(ctx, certs)

    if (server) {
        SSLSetClientSideAuthenticate(ctx, kSSLAuthenticate)
        SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnClientAuth, true)
    } else {
        SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true)
    }

    val ok = handshake(ctx)
    if (!ok) {
        CFRelease(ctx)
        arena.clear()
        error("TLS handshake failed")
    }

    val peer = peerCertificate(ctx) ?: error("no peer certificate")

    return SecureTransportLink(ctx, fd, peer, arena)
}

private class SecureTransportLink(
    private val ctx: SSLContextRef,
    private val fd: Int,
    private val peerCert: ByteArray,
    private val arena: Arena,
) : ConnectedLink {
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        return buffer.usePinned { pinned ->
            memScoped {
                val processed = alloc<size_tVar>()
                val status = SSLRead(ctx, pinned.addressOf(offset), length.convert(), processed.ptr)
                if (status == errSSLClosedGraceful || status == 0) return@memScoped if (status == 0) processed.value.toInt() else -1
                if (status != noErr) return@memScoped -1
                processed.value.toInt()
            }
        }
    }

    override fun write(bytes: ByteArray) {
        var sent = 0
        while (sent < bytes.size) {
            val n = bytes.usePinned { pinned ->
                memScoped {
                    val processed = alloc<size_tVar>()
                    val status = SSLWrite(ctx, pinned.addressOf(sent), (bytes.size - sent).convert(), processed.ptr)
                    if (status != noErr) return@memScoped -1
                    processed.value.toInt()
                }
            }
            if (n <= 0) error("SSL write failed")
            sent += n
        }
    }

    override fun peerCertificate(): ByteArray = peerCert

    override fun close() {
        platform.Security.SSLClose(ctx)
        platform.posix.close(fd)
        arena.clear()
    }
}

private fun handshake(ctx: SSLContextRef): Boolean {
    while (true) {
        when (val status = SSLHandshake(ctx)) {
            noErr -> return true
            errSSLWouldBlock -> continue
            errSSLServerAuthCompleted -> {
                SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, false)
                continue
            }
            errSSLClientAuthCompleted -> {
                SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnClientAuth, false)
                continue
            }
            else -> return false
        }
    }
}

private fun createIdentity(certificate: ByteArray, privateKey: ByteArray): SecIdentityRef? = memScoped {
    val cert = SecCertificateCreateWithData(null, certificate.toCFDataRef()) ?: return@memScoped null
    val key = SecKeyCreateWithData(privateKey.toCFDataRef(), privateKeyAttributes(), null) ?: return@memScoped null
    SecIdentityCreate(null, cert, key)
}

private fun privateKeyAttributes() = memScoped {
    val dict = platform.CoreFoundation.CFDictionaryCreateMutable(null, 2, null, null)
    platform.CoreFoundation.CFDictionaryAddValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA)
    platform.CoreFoundation.CFDictionaryAddValue(dict, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
    dict
}

private fun peerCertificate(ctx: SSLContextRef): ByteArray? = memScoped {
    val trustVar = alloc<SecTrustRefVar>()
    if (SSLCopyPeerTrust(ctx, trustVar.ptr) != noErr) return@memScoped null
    val trust = trustVar.value ?: return@memScoped null
    val chain = SecTrustCopyCertificateChain(trust) ?: return@memScoped null
    try {
        if (CFArrayGetCount(chain) <= 0L) return@memScoped null
        val leaf = CFArrayGetValueAtIndex(chain, 0)?.reinterpret<SecCertificateRef>() ?: return@memScoped null
        val data = SecCertificateCopyData(leaf) ?: return@memScoped null
        try {
            val length = CFDataGetLength(data).toInt()
            if (length <= 0) return@memScoped null
            val ptr = CFDataGetBytePtr(data) ?: return@memScoped null
            ptr.readBytes(length)
        } finally {
            CFRelease(data)
        }
    } finally {
        CFRelease(chain)
    }
}

private fun ByteArray.toCFDataRef() = usePinned { pinned ->
    platform.CoreFoundation.CFDataCreate(null, pinned.addressOf(0).reinterpret(), size.toLong())
}

// The two SecureTransport IO callbacks. They read and write the raw socket,
// which is stored in the connection pointer as a LongVar.

private fun sslReadCallback(
    connection: SSLConnectionRef?,
    data: COpaquePointer?,
    dataLength: CPointer<size_tVar>?,
): platform.darwin.OSStatus {
    val fd = connection!!.reinterpret<LongVar>()!!.get(0).toInt()
    val requested = dataLength!!.get(0).toInt()
    val out = data!!.reinterpret<ByteVar>()
    var total = 0
    while (total < requested) {
        val n = recv(fd, out.plus(total), (requested - total).convert(), 0).toInt()
        if (n <= 0) {
            dataLength.set(0, total.convert())
            return if (n == 0) errSSLClosedGraceful else IO_ERROR.convert()
        }
        total += n
    }
    dataLength.set(0, total.convert())
    return noErr
}

private fun sslWriteCallback(
    connection: SSLConnectionRef?,
    data: COpaquePointer?,
    dataLength: CPointer<size_tVar>?,
): platform.darwin.OSStatus {
    val fd = connection!!.reinterpret<LongVar>()!!.get(0).toInt()
    val requested = dataLength!!.get(0).toInt()
    val src = data!!.reinterpret<ByteVar>()
    var total = 0
    while (total < requested) {
        val n = send(fd, src.plus(total), (requested - total).convert(), 0).toInt()
        if (n < 0) {
            dataLength.set(0, total.convert())
            return if (errno == EAGAIN || errno == EWOULDBLOCK) errSSLWouldBlock else IO_ERROR.convert()
        }
        total += n
    }
    dataLength.set(0, total.convert())
    return noErr
}
