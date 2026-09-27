@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.net

import kotlinx.cinterop.Arena
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVarOf
import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.LongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.cValuesOf
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.plus
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFRelease
import platform.Security.SSLCopyPeerTrust
import platform.Security.SSLAuthenticate
import platform.Security.SSLCreateContext
import platform.Security.SSLConnectionRef
import platform.Security.SSLConnectionType
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
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateCreateWithData
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
import platform.darwin.OSStatus
import platform.darwin.noErr
import platform.posix.EAGAIN
import platform.posix.EWOULDBLOCK
import platform.posix.errno
import platform.posix.recv
import platform.posix.send
import platform.posix.size_tVar

private val IO_ERROR: OSStatus = -36
private val NO_ERR: OSStatus = noErr.toInt()
private val SSL_WOULD_BLOCK: OSStatus = errSSLWouldBlock.toInt()
private val SSL_SERVER_AUTH: OSStatus = errSSLServerAuthCompleted.toInt()
private val SSL_CLIENT_AUTH: OSStatus = errSSLClientAuthCompleted.toInt()
private val SSL_CLOSED_GRACEFUL: OSStatus = errSSLClosedGraceful.toInt()

// kAlwaysAuthenticate: require a client certificate, like the JVM needClientAuth.

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

    val certs = CFArrayCreate(
        null,
        cValuesOf(identity) as CValuesRef<CPointerVarOf<CPointer<out CPointed>>>,
        1,
        null,
    )
    SSLSetCertificate(ctx, certs)
    CFRelease(certs)

    if (server) {
        SSLSetClientSideAuthenticate(ctx, SSLAuthenticate.kAlwaysAuthenticate)
        SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnClientAuth, true)
    } else {
        SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true)
    }

    if (!handshake(ctx)) {
        platform.Security.SSLClose(ctx)
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
                if (status == NO_ERR) processed.value.toInt() else -1
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
                    if (status != NO_ERR) return@memScoped -1
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
            NO_ERR -> return true
            SSL_WOULD_BLOCK -> continue
            SSL_SERVER_AUTH -> {
                SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, false)
                continue
            }
            SSL_CLIENT_AUTH -> {
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
    if (SSLCopyPeerTrust(ctx, trustVar.ptr) != NO_ERR) return@memScoped null
    val trust = trustVar.value ?: return@memScoped null
    val chain = SecTrustCopyCertificateChain(trust) ?: return@memScoped null
    try {
        if (CFArrayGetCount(chain) <= 0L) return@memScoped null
        val leafValue = CFArrayGetValueAtIndex(chain, 0) ?: return@memScoped null
        val leaf: SecCertificateRef = leafValue.reinterpret()
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

private fun sslReadCallback(
    connection: SSLConnectionRef?,
    data: COpaquePointer?,
    dataLength: CPointer<size_tVar>?,
): OSStatus {
    val fd = connection!!.reinterpret<LongVar>()!!.get(0).toInt()
    val requested = dataLength!!.get(0).toInt()
    val out = data!!.reinterpret<ByteVar>()
    var total = 0
    while (total < requested) {
        val n = recv(fd, out.plus(total), (requested - total).convert(), 0).toInt()
        if (n <= 0) {
            dataLength.set(0, total.convert())
            return if (n == 0) SSL_CLOSED_GRACEFUL else IO_ERROR
        }
        total += n
    }
    dataLength.set(0, total.convert())
    return NO_ERR
}

private fun sslWriteCallback(
    connection: SSLConnectionRef?,
    data: COpaquePointer?,
    dataLength: CPointer<size_tVar>?,
): OSStatus {
    val fd = connection!!.reinterpret<LongVar>()!!.get(0).toInt()
    val requested = dataLength!!.get(0).toInt()
    val src = data!!.reinterpret<ByteVar>()
    var total = 0
    while (total < requested) {
        val n = send(fd, src.plus(total), (requested - total).convert(), 0).toInt()
        if (n < 0) {
            dataLength.set(0, total.convert())
            return if (errno == EAGAIN || errno == EWOULDBLOCK) SSL_WOULD_BLOCK else IO_ERROR
        }
        total += n
    }
    dataLength.set(0, total.convert())
    return NO_ERR
}
