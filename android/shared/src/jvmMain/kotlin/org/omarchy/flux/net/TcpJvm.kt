package org.omarchy.flux.net

import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager

internal class JvmStream(internal val socket: Socket) : Stream {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int = input.read(buffer, offset, length)
    override fun write(bytes: ByteArray) {
        output.write(bytes)
        output.flush()
    }

    override fun close() = socket.close()
}

private class JvmTcpServer(private val server: ServerSocket) : TcpServer {
    override fun localPort(): Int = server.localPort
    override fun accept(): Stream? = runCatching { JvmStream(server.accept()) }.getOrNull()
    override fun close() = server.close()
}

actual fun openTcpServer(portRange: IntRange): TcpServer? {
    for (port in portRange) {
        runCatching {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress(port))
            return JvmTcpServer(server)
        }
    }
    return null
}

actual fun tcpConnect(address: String, port: Int): Stream {
    val socket = Socket()
    socket.connect(InetSocketAddress(address, port), 5000)
    socket.keepAlive = true
    socket.tcpNoDelay = true
    return JvmStream(socket)
}

actual fun wrapTls(
    socket: Stream,
    server: Boolean,
    certificate: ByteArray,
    privateKey: ByteArray,
): ConnectedLink {
    val raw = (socket as JvmStream).socket
    val context = SSLContext.getInstance("TLSv1.2").apply {
        init(arrayOf(SingleKeyManager(certificate, privateKey)), arrayOf(AcceptAllTrustManager), null)
    }
    val ssl = context.socketFactory.createSocket(raw, raw.inetAddress.hostAddress, raw.port, true) as SSLSocket
    ssl.enabledProtocols = arrayOf("TLSv1.2")
    ssl.useClientMode = !server
    if (server) ssl.needClientAuth = true
    ssl.soTimeout = 10_000
    ssl.startHandshake()
    ssl.soTimeout = 0
    return SslStream(ssl)
}

private class SslStream(private val ssl: SSLSocket) : ConnectedLink {
    private val input = ssl.inputStream
    private val output = ssl.outputStream
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int = input.read(buffer, offset, length)
    override fun write(bytes: ByteArray) {
        output.write(bytes)
        output.flush()
    }

    override fun peerCertificate(): ByteArray =
        (ssl.session.peerCertificates.firstOrNull() as X509Certificate).encoded

    override fun close() = ssl.close()
}

/** A key manager that always offers the one certificate of this device. */
private class SingleKeyManager(certificate: ByteArray, privateKey: ByteArray) : X509ExtendedKeyManager() {
    private val alias = "flux"
    private val cert: X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(certificate.inputStream()) as X509Certificate
    private val key: PrivateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKey))

    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(alias)
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = alias
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(alias)
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = alias
    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) = alias
    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?) = alias
    override fun getCertificateChain(alias: String?): Array<X509Certificate> = arrayOf(cert)
    override fun getPrivateKey(alias: String?): PrivateKey = key
}

/** Accepts every certificate. The link code pins certificates after the handshake. */
private object AcceptAllTrustManager : X509ExtendedTrustManager() {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = Unit
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = Unit
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = Unit
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
